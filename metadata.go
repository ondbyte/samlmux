package samlmux

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

type MetaData struct {
	*types.EntityDescriptor
}

func NewMetDataFromURL(url string) (*MetaData, error) {
	res, err := http.Get(url)
	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(b, metadata)
	if err != nil {
		return nil, err
	}
	return &MetaData{metadata}, nil
}

func NewMetDataFromFile(filePath string) (*MetaData, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(b, metadata)
	if err != nil {
		return nil, err
	}
	return &MetaData{metadata}, nil
}

func (md *MetaData) IdpSsoUrl() (string, error) {
	if len(md.IDPSSODescriptor.SingleSignOnServices) == 0 {
		return "", fmt.Errorf("IDP metadata seems invalid, no SSO urls found")
	}
	return md.IDPSSODescriptor.SingleSignOnServices[0].Location, nil
}

func (md *MetaData) IdpCertStore() (*dsig.MemoryX509CertificateStore, error) {
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}
	for _, kd := range md.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return nil, fmt.Errorf("metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return nil, err
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, err
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}
	return &certStore, nil
}
