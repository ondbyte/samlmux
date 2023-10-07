package samlmux

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

type ServiceProvider struct {
	*tls.Certificate
	*saml2.SAMLServiceProvider
	*log.Logger
}

func (sp *ServiceProvider) signatureOf(dataToVerifyStr string) (string, error) {
	// Generate the header.
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerStr := base64.StdEncoding.EncodeToString(headerBytes)
	// Sign the token.
	hash := hmac.New(sha256.New, sp.PrivateKey.(rsa.PrivateKey).N.Bytes())
	hash.Write([]byte(headerStr + "." + dataToVerifyStr))

	signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return signature, nil
}

// expects "redirectTo" or "redirect_to"  param, value should be a valid URL to where the browser will be lead
// once auth flow is done
func (sp *ServiceProvider) HandleSamlAuth(
	w http.ResponseWriter,
	r *http.Request,
) {
	redirectTo := r.URL.Query().Get("redirectTo")
	if redirectTo == "" {
		redirectTo = r.URL.Query().Get("redirect_to")
	}
	if redirectTo == "" {
		http.Error(w, "error:see server logs", http.StatusTeapot)
		sp.Println("ServiceProvider.HandleSamlAuth expects request to contain a param named either 'redirect_to' or 'redirectTo' to be present")
		return
	}
	redirectToUrl, err := url.Parse(redirectTo)
	if err != nil {
		sp.Println(
			"ServiceProvider.HandleSamlAuth expects request the'redirect_to' or 'redirectTo' param to be a valid URL," +
				"the param value is: " +
				redirectTo,
		)
		http.Error(w, "error:see server logs", http.StatusTeapot)
		return
	}

	// as relayState cannot be more than 80 bytes, we will set cookie with the data and key of the
	// cookie as the relayState, relaystate will be the signature of the data in the cookie

	// data we weill verify in the acs callback
	dataToVerify := map[string]string{
		"redirect_to": redirectToUrl.String(),
	}
	dataToVerifyBytes, err := json.Marshal(dataToVerify)
	if err != nil {
		http.Error(w, "error:see server logs", http.StatusInternalServerError)
		sp.Println(fmt.Sprint(err))
		return
	}
	dataToVerifyStr := base64.StdEncoding.EncodeToString(dataToVerifyBytes)

	signature, err := sp.signatureOf(dataToVerifyStr)
	if err != nil {
		http.Error(w, "error:see server logs", http.StatusInternalServerError)
		sp.Println(err)
		return
	}

	// realystate will be the signature of the dataToVerify
	relayState := signature

	cookie := &http.Cookie{
		// relayState will be tha name of the cookie
		Name:     relayState,
		Value:    dataToVerifyStr + "." + signature,
		Secure:   true,
		HttpOnly: true,
		MaxAge:   30,
	}
	http.SetCookie(w, cookie)
	authUrl, err := sp.BuildAuthURL(relayState)
	if err != nil {
		http.Error(w, "error:see server logs", http.StatusInternalServerError)
		sp.Println(err)
		return
	}
	// finally redirect the browser to saml auth url
	// once user completes the auth, HandleAcs takes over
	http.Redirect(w, r, authUrl, http.StatusFound)
}

func (sp *ServiceProvider) HandleAcs(
	w http.ResponseWriter,
	r *http.Request,
) {
	// verify relayState first
	relayState := r.URL.Query().Get("relayState")
	// cookie we set while authentication initiation in HandleSamlAuth
	cookie, err := r.Cookie(relayState)
	if err == http.ErrNoCookie {
		// cookie is not found, something fishy
		http.Error(w, "", http.StatusTeapot)
		return
	}
	// verify the cookie
	splitCookie := strings.Split(cookie.Value, ".")
	// should have 2 parts dataToVerifyStr + signature
	if len(splitCookie) != 2 {
		// more fishy
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("the len of the splitted cookie value should be 2 but it is %v", len(splitCookie)))
		return
	}
	// 2nd value in splitted cookie should be equal to relayState
	if relayState != splitCookie[1] {
		// woa, fish
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("relayState should be eq to 2nd value in the splitCookie "))
		return
	}
	// verify signature of the dataToVerify in the cookie matches the signature in the cookie
	signature, err := sp.signatureOf(splitCookie[0])
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		sp.Println(fmt.Sprintf("failed generate the signature of the dataToVerify in the cookie"))
		return
	}
	if signature != splitCookie[1] {
		// signature doesn't match,someone is trying very hard to break in
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("signature doesn't match,someone is trying very hard to break in"))
		return
	}

	// now verify the SAML response from the IDP
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("failed to parse the form data in the HandleAcs"))
		return
	}
	assertionInfo, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("unable to retrieve assertion from SAMLResponse"))
		return
	}

	if assertionInfo.WarningInfo.InvalidTime || assertionInfo.WarningInfo.NotInAudience {
		http.Error(w, "", http.StatusTeapot)
		sp.Println(fmt.Sprintf("SAMLResponse has warnings"))
		return
	}

	b, err := xml.Marshal(assertionInfo.Values)
	if err != nil {
		panic(err)
	}
	onSuccess(w, r, string(b))
}

// acsUrl: most of the time https://<entityId>/saml/acs
func NewServiceProvider(
	entityId string,
	acsUrl string,
	cert *tls.Certificate,
	idpMetadata *MetaData,
) (
	*ServiceProvider,
	error,
) {
	idpSsoUrl, err := idpMetadata.IdpSsoUrl()
	if err != nil {
		return nil, err
	}
	idpCertStore, err := idpMetadata.IdpCertStore()
	if err != nil {
		return nil, err
	}

	return &ServiceProvider{
		SAMLServiceProvider: &saml2.SAMLServiceProvider{
			IdentityProviderSSOURL:      idpSsoUrl,
			IdentityProviderIssuer:      idpMetadata.EntityID,
			ServiceProviderIssuer:       entityId,
			AudienceURI:                 entityId,
			IDPCertificateStore:         idpCertStore,
			SPKeyStore:                  dsig.TLSCertKeyStore(*cert),
			AssertionConsumerServiceURL: acsUrl,
		},
		Logger:      log.Default(),
		Certificate: cert,
	}, nil
}
