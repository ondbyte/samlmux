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

var (
	STRING_SEPERATOR = ".ONDBYTE."
)

type cookieData struct {
	Uuid         string `json:"uuid"`
	SessionIndex string `json:"sessionIndex"`
	NameId       string `json:"nameId"`
}

type OnLoginDone func(w http.ResponseWriter, r *http.Request, data string)
type OnLogOutDone func(w http.ResponseWriter, r *http.Request, data string)

type ServiceProviderOptions struct {
	// this is where your service will run at for ex: https://example.com
	// or https://localhost:3000
	// this is used as your entity id in your SP metadata
	// to ovverride this set the OverrideEntityId
	// should be non empty
	ServiceRunsAt string
	// ovverrides ServiceRunsAt
	OverrideEntityId string
	// path where sso initiation begins
	// if this is /saml/sso your users can initiate login by going to
	// https://example.com/saml/sso,
	// defaults to "/saml/sso"
	SsoPath string
	// acs path, if this is /saml/acs, once service starts running will look like https://example.com/saml/acs,
	// defaults to "/saml/acs"
	AcsPath string
	// logout path for logout initiated by a idp,
	// for example when a user logs out from a idp dashboard,
	// this will be
	// if this is /saml/slo, once service starts running will look like https://example.com/saml/slo,
	// defaults to "/saml/slo"
	SloPath string
	// your SP's meta data will be available at the is path
	MetaDataPath string

	// use this to redirect the user once acs is done
	// if the authentication is successful the data parameter will be non empty xml data
	// you dont have to verify the the data, you just have to consult the data for
	// emailId or name/s to issue your own token/s
	OnLoginDone OnLoginDone

	// use this to know when user initiates logout, invalidate session tokens
	OnLogOutDone OnLogOutDone

	// a signing certificate to use with the library
	// should be non nil
	Cert *tls.Certificate

	// metadata of the idp like microsoft entra,okta etc,
	// should be non nil
	IdpMetadata *MetaData
	// Logger to log all the library debug messages
	Logger *log.Logger
}

// your service provider to run
type ServiceProvider struct {
	OnLoginDone  OnLoginDone
	OnLogOutDone OnLogOutDone
	*http.ServeMux
	*tls.Certificate
	*saml2.SAMLServiceProvider
	*log.Logger
}

func (sp *ServiceProvider) signatureOf(data string) (string, error) {
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
	hash.Write([]byte(headerStr + STRING_SEPERATOR + data))

	signature := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return signature, nil
}

func (sp *ServiceProvider) handleSso(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUrl, err := sp.BuildAuthURL("")
	if err != nil {
		http.Error(w, "error:see server logs", http.StatusInternalServerError)
		sp.Println(err)
		return
	}
	// finally redirect the browser to saml auth url
	// once user completes the auth, HandleAcs takes over
	http.Redirect(w, r, authUrl, http.StatusFound)
}

func (sp *ServiceProvider) handleSlo(
	w http.ResponseWriter,
	r *http.Request,
) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "error:see server logs", http.StatusTeapot)
		sp.Printf("failed to ParseForm on request: %v", err)
		return
	}
	logoutRequestEncoded := r.FormValue("SAMLRequest")
	if logoutRequestEncoded != "" {
		logoutRequest, err := sp.ValidateEncodedLogoutRequestPOST(logoutRequestEncoded)
		if err != nil {
			http.Error(w, "error:see server logs", http.StatusInternalServerError)
			sp.Printf("failed to ValidateEncodedLogoutRequestPOST : %v", err)
			return
		}

		// logout request is from valid idp, continue
		b, err := xml.Marshal(logoutRequest)
		if err != nil {
			http.Error(w, "see server logs for error", http.StatusInternalServerError)
			sp.Printf("unable to marshal saml logout request err: %v", err)
			return
		}
		sp.OnLogOutDone(w, r, string(b))
		return
	}
	logoutResponseEncoded := r.FormValue("SAMLResponse")
	if logoutResponseEncoded != "" {
		// its logout response
		logoutResponse, err := sp.ValidateEncodedLogoutResponsePOST(logoutResponseEncoded)
		if err != nil {
			http.Error(w, "error:see server logs", http.StatusTeapot)
			sp.Printf("failed to ValidateEncodedLogoutResponsePOST on SAMLResponse: %v", err)
			return
		}

		// logout response is from valid idp, continue
		b, err := xml.Marshal(logoutResponse)
		if err != nil {
			http.Error(w, "see server logs for error", http.StatusInternalServerError)
			sp.Printf("unable to marshal saml logout request err: %v", err)
			return
		}
		sp.OnLogOutDone(w, r, string(b))
		return
	}

	// our user is trying to logout from a browser
	// get session index from cookie
	cookie, err := r.Cookie("samlmux")
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("unable to get samlmux cookie: %v", err)
		return
	}
	cookieData, err := sp.validateSignedCookie(cookie)
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("unable to verify samlmux cookie: %v", err)
		return
	}
	if cookieData.SessionIndex == "" || cookieData.NameId == "" {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("invalid cookie data: %v", err)
		return
	}

	redirectUrl, err := sp.BuildLogoutURL("", cookieData.NameId, cookieData.SessionIndex)
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("unable to BuildLogoutURLRedirect: %v", err)
		return
	}
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}

func (sp *ServiceProvider) handleAcs(
	w http.ResponseWriter,
	r *http.Request,
) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusTeapot)
		sp.Printf("failed to parse the form data in the HandleAcs")
		return
	}
	encodedResponse := r.FormValue("SAMLResponse")
	assertionInfo, err := sp.RetrieveAssertionInfo(encodedResponse)
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusTeapot)
		sp.Printf("unable to retrieve assertion from SAMLResponse")
		return
	}

	if assertionInfo.WarningInfo.InvalidTime || assertionInfo.WarningInfo.NotInAudience {
		http.Error(w, "see server logs for error", http.StatusTeapot)
		sp.Printf("SAMLResponse has warnings")
		return
	}

	b, err := xml.Marshal(assertionInfo)
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("unable to marshal saml response err: %v", err)
		return
	}
	data := &cookieData{
		Uuid:         uuid.NewV4().String(),
		SessionIndex: assertionInfo.SessionIndex,
		NameId:       assertionInfo.NameID,
	}
	c, err := sp.getSignedCookie(data)
	if err != nil {
		http.Error(w, "see server logs for error", http.StatusInternalServerError)
		sp.Printf("unable to generate signed cookie, err: %v", err)
		return
	}
	http.SetCookie(w, c)
	sp.OnLoginDone(w, r, string(b))
}

func (sp *ServiceProvider) getSignedCookie(data *cookieData) (*http.Cookie, error) {
	dataToVerifyBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	dataToVerifyStr := base64.StdEncoding.EncodeToString(dataToVerifyBytes)
	signature, err := sp.signatureOf(dataToVerifyStr)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
			Name:  "samlmux",
			Value: dataToVerifyStr + STRING_SEPERATOR + signature,
		},
		nil
}

// validates samlmux cookie and returns data in it if signature coparison is successful
// just to make sure our cookie isnt tampered with
func (sp *ServiceProvider) validateSignedCookie(cookie *http.Cookie) (*cookieData, error) {
	splittedCookieVal := strings.Split(cookie.Value, STRING_SEPERATOR)
	if len(splittedCookieVal) != 2 {
		return nil, fmt.Errorf("cookie value should be two part seperated by a '.'")
	}
	dataToVerifyEncoded := splittedCookieVal[0]
	expectedSignature := splittedCookieVal[1]

	signature, err := sp.signatureOf(dataToVerifyEncoded)
	if err != nil {
		return nil, err
	}
	if expectedSignature != signature {
		// cookie is tampered with
		return nil, fmt.Errorf("cookie is tampered")
	}
	dataToVerifyDecoded := make([]byte, len(dataToVerifyEncoded))
	i, err := base64.StdEncoding.Decode(dataToVerifyDecoded, []byte(dataToVerifyEncoded))
	dataToVerifyDecoded = dataToVerifyDecoded[:i]
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 encoded string")
	}

	data := new(cookieData)
	err = json.Unmarshal(dataToVerifyDecoded, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (sp *ServiceProvider) MetadataStr() (string, error) {
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

func (sp *ServiceProvider) handlMetaData(
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

// creates a new instance of ServiceProvider with configurable options
// this SP will manage everything for you validating signatures of the SAML requests and SAML responses
// all you had to manage OnLoginDone and OnLogoutDone
// ie issue a new session token/ create new user etc in OnLoginDone
// and remove user session etc OnLogoutDone
// data parmeter on these callbacks are the details provided by the idp for the user in action
func NewServiceProviderWithOption(opts *ServiceProviderOptions) *ServiceProvider {
	if opts.ServiceRunsAt == "" {
		panic("ServiceRunsAt cannot be empty")
	}
	if opts.SsoPath == "" {
		opts.SsoPath = "/saml/sso"
	}
	if opts.AcsPath == "" {
		opts.AcsPath = "/saml/acs"
	}
	if opts.SloPath == "" {
		opts.SloPath = "/saml/slo"
	}
	if opts.MetaDataPath == "" {
		opts.MetaDataPath = "/saml/metadata"
	}
	if opts.OnLoginDone == nil {
		opts.OnLoginDone = fallBackOnLoginDone
	}
	if opts.OnLogOutDone == nil {
		opts.OnLogOutDone = fallBackOnLogoutDone
	}
	if opts.Cert == nil {
		panic("Cert cannot be nil")
	}
	if opts.IdpMetadata == nil {
		panic("IdpMetadata cannot be nil")
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	idpSsoUrl, err := opts.IdpMetadata.IdpSsoUrl()
	if err != nil {
		panic(fmt.Sprintf("cannot get IdpSsoUrl from idp metadata: %v", err))
	}
	idpSloUrl, err := opts.IdpMetadata.IdpSloUrl()
	if err != nil {
		panic(fmt.Sprintf("cannot get IdpSloUrl from idp metadata: %v", err))
	}
	entityId := opts.ServiceRunsAt
	if opts.OverrideEntityId != "" {
		entityId = opts.OverrideEntityId
	}
	idpCertStore, err := opts.IdpMetadata.IdpCertStore()
	if err != nil {
		panic(fmt.Sprintf("cannot get IdpCertStore(certificate) from idp metadata: %v", err))
	}
	s := &ServiceProvider{
		ServeMux:     http.NewServeMux(),
		Logger:       opts.Logger,
		OnLoginDone:  opts.OnLoginDone,
		OnLogOutDone: opts.OnLogOutDone,
		Certificate:  opts.Cert,
		SAMLServiceProvider: &saml2.SAMLServiceProvider{
			AssertionConsumerServiceURL: fmt.Sprintf("%v%v", opts.ServiceRunsAt, opts.AcsPath),
			IdentityProviderSLOURL:      idpSloUrl,
			IdentityProviderSSOURL:      idpSsoUrl,
			IdentityProviderIssuer:      opts.IdpMetadata.EntityID,
			ServiceProviderIssuer:       entityId,
			AudienceURI:                 entityId,
			IDPCertificateStore:         idpCertStore,
			SPKeyStore:                  dsig.TLSCertKeyStore(*opts.Cert),
			SignAuthnRequests:           true,
			ServiceProviderSLOURL:       fmt.Sprintf("%v%v", opts.ServiceRunsAt, opts.SloPath),
		},
	}
	s.HandleFunc(opts.SsoPath, s.handleSso)
	s.HandleFunc(opts.AcsPath, s.handleAcs)
	s.HandleFunc(opts.MetaDataPath, s.handlMetaData)
	s.HandleFunc(opts.SloPath, s.handleSlo)
	return s
}

func fallBackOnLoginDone(w http.ResponseWriter, r *http.Request, data string) {
	w.Write([]byte(fmt.Sprintf(`
	<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            text-align: center;
            padding: 50px;
        }

        .container {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Login Successful!</h1>
        <p>You have successfully logged in to your account.</p>
        <p>you have got the following SAMLResponse.</p>
        <p>%v</p>
    </div>
</body>

</html>

	`, data)))
}

func fallBackOnLogoutDone(w http.ResponseWriter, r *http.Request, data string) {
	w.Write([]byte(fmt.Sprintf(`
	<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logout Success</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            text-align: center;
            padding: 50px;
        }

        .container {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Logout Successful!</h1>
        <p>You have successfully logged out of your account.</p>
        <p>you have got the following SAMLRequest/SAMLResponse (logout).</p>
        <p>%v</p>
    </div>
</body>

</html>

	`, data)))
}
