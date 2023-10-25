package saml_http

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

var (
	STRING_SEPERATOR = ".ONDBYTE."
)

type SessionData struct {
	SessionIndex string    `json:"sessionIndex"`
	NameId       string    `json:"nameId"`
	ValidTill    time.Time `json:"validTill"`
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
	// should be non empty
	SsoPath string
	// acs path, if this is /saml/acs, once service starts running will look like https://example.com/saml/acs,
	// should be non empty
	AcsPath string
	// logout path for logout initiated by a idp,
	// for example when a user logs out from a idp dashboard,
	// this will be
	// if this is /saml/slo, once service starts running will look like https://example.com/saml/slo,
	// should be non empty
	SloPath string
	// your SP's meta data will be available at the is path
	// should be non empty
	MetaDataPath string

	// a signing certificate to use with the library
	// should be non nil
	SigningCert func() tls.Certificate

	// metadata of the idp like microsoft entra,okta etc,
	// should be non nil
	IdpMetadata *MetaData
	// Logger to log all the library debug messages
	Logger *log.Logger
}

// your service provider to run
type ServiceProvider struct {
	signingCert func() (tls.Certificate, error)
	*extendedSp
	*log.Logger
}

func (sp *ServiceProvider) HandleSso(
	w http.ResponseWriter,
	r *http.Request,
) {
	authUrl, err := sp.BuildAuthURL("")
	if err != nil {
		http.Error(w, "see server logs", http.StatusInternalServerError)
		sp.Println(err)
		return
	}
	// finally redirect the browser to saml auth url
	// once user completes the auth, HandleAcs takes over
	http.Redirect(w, r, authUrl, http.StatusFound)
}

// onLogout will be called when logout flow is done, you should reroute the user here
// onIdpInitiatesLogout is called when IDP initiates the logout, a NameId(mostly email id) will be delivered with it, so you can logout or
// invalidate the session for that user, onLogout will never be called when the IDP initiates the logout
func (sp *ServiceProvider) HandleSlo(
	w http.ResponseWriter,
	r *http.Request,
	sd SessionData,
	onLogout func(error),
	onIdpInitiatesLogout func(nameId string),
) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "see server logs", http.StatusTeapot)
		sp.Printf("failed to ParseForm on request: %v", err)
		return
	}
	logoutRequestEncoded := r.FormValue("SAMLRequest")
	if logoutRequestEncoded != "" {
		logoutRequest, err := sp.ValidateEncodedLogoutRequestPOST(logoutRequestEncoded)
		if err != nil {
			http.Error(w, "see server logs", http.StatusTeapot)
			sp.Printf("unable to validate request signature: %v", err)
			return
		}
		onIdpInitiatesLogout(logoutRequest.NameID.Value)
		return
	}

	logoutResponseEncoded := r.FormValue("SAMLResponse")
	if logoutResponseEncoded != "" {
		_, err := sp.ValidateEncodedLogoutResponsePOST(logoutResponseEncoded)
		if err != nil {
			onLogout(err)
			return
		}
		onLogout(nil)
		return
	}
	if sd.SessionIndex == "" || sd.NameId == "" {
		onLogout(fmt.Errorf("session data has empty value/s"))
		return
	}

	redirectUrl, err := sp.BuildLogoutURL("", sd.NameId, sd.SessionIndex)
	if err != nil {
		onLogout(err)
		return
	}
	http.Redirect(w, r, redirectUrl, http.StatusFound)
}

// onLogin will be called with non nil session data when login  is successful or else error
func (sp *ServiceProvider) HandleAcs(
	w http.ResponseWriter,
	r *http.Request,
	onLogin func(*SessionData, error),
) {
	err := r.ParseForm()
	if err != nil {
		onLogin(nil, fmt.Errorf("failed to parse the form data in the HandleAcs: %v", err))
		return
	}
	encodedResponse := r.FormValue("SAMLResponse")
	assertionInfo, err := sp.RetrieveAssertionInfo(encodedResponse)
	if err != nil {
		onLogin(nil, fmt.Errorf("unable to retrieve assertion from SAMLResponse: %v", err))
		return
	}

	if assertionInfo.WarningInfo.InvalidTime || assertionInfo.WarningInfo.NotInAudience {
		onLogin(nil, fmt.Errorf("SAMLResponse has warnings: %v", err))
		return
	}
	if assertionInfo.Assertions[0].Conditions.NotOnOrAfter == "" {
		onLogin(nil, fmt.Errorf("SAMLResponse has invalid NotOnOrAfter"))
		return
	}
	validTill, err := time.Parse(time.RFC3339, assertionInfo.Assertions[0].Conditions.NotOnOrAfter)
	if err != nil {
		onLogin(nil, fmt.Errorf("unable to parse NotOnOrAfter/validity from SAMLResponse: %v", err))
		return
	}
	data := &SessionData{
		SessionIndex: assertionInfo.SessionIndex,
		NameId:       assertionInfo.NameID,
		ValidTill:    validTill,
	}
	onLogin(data, nil)
}

func (sp *ServiceProvider) MetadataStr() (string, error) {
	md, err := sp.MetadataWithSLO(int64(time.Hour * 24 * 14)) //14 days
	if err != nil {
		return "", err
	}
	mdBytes, err := xml.Marshal(md)
	if err != nil {
		return "", err
	}
	return string(mdBytes), nil
}

func (sp *ServiceProvider) HandlMetaData(
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
// this provides methods to handle sso,acs,slo,metadtata calls to your application
func NewServiceProviderWithOption(opts *ServiceProviderOptions) *ServiceProvider {
	if opts.ServiceRunsAt == "" {
		panic("ServiceRunsAt cannot be empty")
	}
	if opts.SsoPath == "" {
		panic("SsoPath is required")
	}
	if opts.AcsPath == "" {
		panic("AcsPath is required")
	}
	if opts.SloPath == "" {
		panic("SloPath is required")
	}
	if opts.MetaDataPath == "" {
		panic("MetaDataPath is required")
	}
	if opts.SigningCert == nil {
		panic("SigningCert cannot be nil")
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
		Logger: opts.Logger,
		extendedSp: &extendedSp{
			SAMLServiceProvider: &saml2.SAMLServiceProvider{
				AssertionConsumerServiceURL: fmt.Sprintf("%v%v", opts.ServiceRunsAt, opts.AcsPath),
				IdentityProviderSLOURL:      idpSloUrl,
				IdentityProviderSSOURL:      idpSsoUrl,
				IdentityProviderIssuer:      opts.IdpMetadata.EntityID,
				ServiceProviderIssuer:       entityId,
				AudienceURI:                 entityId,
				IDPCertificateStore:         idpCertStore,
				SPKeyStore:                  dsig.TLSCertKeyStore(opts.SigningCert()),
				SignAuthnRequests:           true,
				ServiceProviderSLOURL:       fmt.Sprintf("%v%v", opts.ServiceRunsAt, opts.SloPath),
			},
		},
	}
	return s
}
