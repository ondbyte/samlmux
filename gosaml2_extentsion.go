package saml_http

// gosaml2 needed some extra methods, which are as follows

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
)

type extendedSp struct {
	*saml2.SAMLServiceProvider
}

func (sp *extendedSp) buildLogoutURLFromDocument(relayState, binding string, doc *etree.Document) (string, error) {
	parsedUrl, err := url.Parse(sp.IdentityProviderSLOURL)
	if err != nil {
		return "", err
	}

	logoutRequest, err := doc.WriteToString()
	if err != nil {
		return "", err
	}

	buf := &bytes.Buffer{}

	fw, err := flate.NewWriter(buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("flate NewWriter error: %v", err)
	}

	_, err = fw.Write([]byte(logoutRequest))
	if err != nil {
		return "", fmt.Errorf("flate.Writer Write error: %v", err)
	}

	err = fw.Close()
	if err != nil {
		return "", fmt.Errorf("flate.Writer Close error: %v", err)
	}

	qs := parsedUrl.Query()

	qs.Add("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))

	if relayState != "" {
		qs.Add("RelayState", relayState)
	}

	if binding == saml2.BindingHttpRedirect {
		// Sign URL encoded query (see Section 3.4.4.1 DEFLATE Encoding of saml-bindings-2.0-os.pdf)
		ctx := sp.SigningContext()
		qs.Add("SigAlg", ctx.GetSignatureMethodIdentifier())
		var rawSignature []byte
		//qs.Encode() sorts the keys (See https://golang.org/pkg/net/url/#Values.Encode).
		//If RelayState parameter is present then RelayState parameter
		//will be put first by Encode(). Hence encode them separately and concatenate.
		//Signature string has to have parameters in the order - SAMLRequest=value&RelayState=value&SigAlg=value.
		//(See Section 3.4.4.1 saml-bindings-2.0-os.pdf).
		var orderedParams = []string{"SAMLRequest", "RelayState", "SigAlg"}

		var paramValueMap = make(map[string]string)
		paramValueMap["SAMLRequest"] = base64.StdEncoding.EncodeToString(buf.Bytes())
		if relayState != "" {
			paramValueMap["RelayState"] = relayState
		}
		paramValueMap["SigAlg"] = ctx.GetSignatureMethodIdentifier()

		ss := ""

		for _, k := range orderedParams {
			v, ok := paramValueMap[k]
			if ok {
				//Add the value after URL encoding.
				u := url.Values{}
				u.Add(k, v)
				e := u.Encode()
				if ss != "" {
					ss += "&" + e
				} else {
					ss = e
				}
			}
		}

		//Now generate the signature on the string of ordered parameters.
		if rawSignature, err = ctx.SignString(ss); err != nil {
			return "", fmt.Errorf("unable to sign query string of redirect URL: %v", err)
		}

		// Now add base64 encoded Signature
		qs.Add("Signature", base64.StdEncoding.EncodeToString(rawSignature))
	}

	//Here the parameters may appear in any order.
	parsedUrl.RawQuery = qs.Encode()
	return parsedUrl.String(), nil
}

// BuildAuthURL builds redirect URL to be sent to principal
func (sp *extendedSp) BuildLogoutURL(relayState string, nameId, sessionIndex string) (string, error) {
	doc, err := sp.BuildLogoutRequestDocument(nameId, sessionIndex)
	if err != nil {
		return "", err
	}
	return sp.buildLogoutURLFromDocument(relayState, saml2.BindingHttpPost, doc)
}
