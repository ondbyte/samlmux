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
	"strings"
	"time"

	saml2 "github.com/ondbyte/samlmux/saml2"
	"github.com/ondbyte/samlmux/saml2/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

type AfterAcsRedirect func(w http.ResponseWriter, r *http.Request, data string)

type ServiceProvider struct {
	*tls.Certificate
	*saml2.SAMLServiceProvider
	afterAcsRedirect AfterAcsRedirect
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
	hash := hmac.New(sha256.New, sp.PrivateKey.(*rsa.PrivateKey).N.Bytes())
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
	// as relayState cannot be more than 80 bytes, we will set cookie with the data and key of the
	// cookie as the relayState, relaystate will be the signature of the data in the cookie

	// data we weill verify in the acs callback
	dataToVerify := map[string]string{
		"uuid": uuid.NewV4().String(),
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
	sp.afterAcsRedirect(w, r, string(b))
}

func (sp *ServiceProvider) MetadataStr() (string, error) {
	// TODO MetaDataWithSLO parameter requires a name fix
	md, err := sp.MetadataWithSLO(time.Duration(int64(time.Hour) * 24 * 14)) //14 days
	if err != nil {
		return "", err
	}
	mdBytes, err := xml.Marshal(md)
	if err != nil {
		return "", err
	}
	return string(mdBytes), nil
}

func (sp *ServiceProvider) HandleMetaData(
	w http.ResponseWriter,
	r *http.Request,
) {
	mdStr, err := sp.MetadataStr()
	if err != nil {
		http.Error(w, "see server logs", http.StatusInternalServerError)
		sp.Println("error calling xml.Marshal on metadata")
		sp.Println(err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(mdStr))
}

// entityId is the entityId in our metadata.
//
// acsUrl: most of the time https://<entityId>/saml/acs
//
// logoutUrl will be where a user can initiate logout
//
// cert
//
// idpMetaData is the metdata of the idp (ex: AZURE,okta)
//
// afterAcsRedirect is the redirect handler once the SAML ACS is done.
// if the SAML ACS is successful the data variable will be non nil, using this data you can issue a token and then lead
// the browser to a URL
func NewServiceProvider(
	entityId string,
	acsUrl string,
	logoutUrl string,
	cert *tls.Certificate,
	idpMetadata *MetaData,
	afterAcsRedirect AfterAcsRedirect,
	logger *log.Logger,
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
			SignAuthnRequests:           true,
			ServiceProviderSLOURL:       logoutUrl,
		},
		Logger:           logger,
		Certificate:      cert,
		afterAcsRedirect: afterAcsRedirect,
	}, nil
}
