package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ondbyte/saml_http"
)

var (
	addressOfOurService = "https://localhost:3000"
	acsPath             = "/saml/acs"
	ssoPath             = "/saml/sso"
	sloPath             = "/saml/slo"
	metaDataPath        = "/saml/metadata"
)

func onAuthFlowDone(w http.ResponseWriter, r *http.Request, data string) {
	w.Write([]byte(`
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
        <!-- You can add more content here like user information, links, etc. -->
    </div>
</body>

</html>

	`))
}

func samlTestIdMetaData() *saml_http.MetaData {
	d, err := saml_http.NewMetDataFromURL("https://samltest.id/saml/idp")
	if err != nil {
		panic(err)
	}
	return d
}

func idpMetaDataFromFile() *saml_http.MetaData {
	idpMetaData, err := saml_http.NewMetDataFromFile("./example_idp_metadata.xml")
	if err != nil {
		panic(err)
	}
	return idpMetaData
}

func main() {
	var sessionData *saml_http.SessionData
	samlservice := saml_http.NewServiceProviderWithOption(
		&saml_http.ServiceProviderOptions{
			ServiceRunsAt: "https://localhost:3000",
			SsoPath:       ssoPath,
			AcsPath:       acsPath,
			SloPath:       sloPath,
			MetaDataPath:  metaDataPath,
			SigningCert: func() tls.Certificate {
				c, err := tls.LoadX509KeyPair("./example.cert", "./example.key")
				if err != nil {
					panic(err)
				}
				return c
			},
			IdpMetadata: idpMetaDataFromFile(),
			Logger:      log.Default(),
		},
	)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("saml_http example service\n"))
		if sessionData != nil {
			w.Write([]byte(fmt.Sprintf("has saml session with data: %v", sessionData)))
		} else {
			w.Write([]byte(fmt.Sprintf("has no saml session")))
		}
	})

	http.HandleFunc(ssoPath, func(w http.ResponseWriter, r *http.Request) {
		// you can check the session
		if sessionData != nil && sessionData.ValidTill.After(time.Now()) {
			// valid session, you need not to continue
		}
		samlservice.HandleSso(w, r)
	})

	http.HandleFunc(acsPath, func(w http.ResponseWriter, r *http.Request) {
		// you can check the session
		if sessionData != nil && sessionData.ValidTill.After(time.Now()) {
			// valid session, you need not to continue
		}
		samlservice.HandleAcs(w, r, func(sd *saml_http.SessionData, err error) {
			if err != nil {
				// a error happened while logging in
				http.Error(w, fmt.Sprintf("login failed due to err: %v", err), http.StatusTeapot)
				return
			}
			sessionData = sd
			w.Write([]byte("login success"))
		})
	})

	http.HandleFunc(sloPath, func(w http.ResponseWriter, r *http.Request) {
		// you can check the session
		if sessionData != nil && sessionData.ValidTill.After(time.Now()) {
			// valid session, you need not to continue
		}
		samlservice.HandleSlo(w, r, *sessionData, func(err error) {
			if err != nil {
				http.Error(w, fmt.Sprintf("logout failed due to err: %v", err), http.StatusTeapot)
				return
			}
			w.Write([]byte(fmt.Sprintf("user with NameId %v logged out", sessionData.NameId)))
		},
			func(nameId string) {
				if sessionData.NameId == nameId {
					sessionData = nil
					w.Write([]byte("user logged out by idp"))
					return
				}
				w.WriteHeader(http.StatusTeapot)
				w.Write([]byte("wrong nameId sent by idp to logout"))
			},
		)
	})

	http.HandleFunc(metaDataPath, func(w http.ResponseWriter, r *http.Request) {
		samlservice.HandlMetaData(w, r)
	})
	// write our metadata to a file
	mdStr, err := samlservice.MetadataStr()
	if err != nil {
		panic(err)
	}

	file, err := os.Create("./example_sp_metadata.xml")
	if err != nil {
		panic(err)
	}
	_, err = file.Write([]byte(mdStr))
	if err != nil {
		panic(err)
	}
	file.Close()
	fmt.Println(`example: written sp meta data to file 'example_sp_metadata.xml' also consult the metadata url for the same`)
	fmt.Printf("login at %v%v", addressOfOurService, ssoPath)
	http.ListenAndServeTLS(":3000", "./example.cert", "./example.key", http.DefaultServeMux)
}
