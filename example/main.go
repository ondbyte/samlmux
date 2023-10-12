package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ondbyte/samlmux"
)

var (
	addressOfOurService = "https://localhost:3000"
	acsPath             = "/saml/acs"
	loginPath           = "/saml/sso"
	logoutPath          = "/saml/slo"
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

func samlTestIdMetaData() *samlmux.MetaData {
	d, err := samlmux.NewMetDataFromURL("https://samltest.id/saml/idp")
	if err != nil {
		panic(err)
	}
	return d
}

func idpMetaDataFromFile() *samlmux.MetaData {
	idpMetaData, err := samlmux.NewMetDataFromFile("./example_idp_metadata.xml")
	if err != nil {
		panic(err)
	}
	return idpMetaData
}
func main() {
	c, err := tls.LoadX509KeyPair("./example.cert", "./example.key")
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("samlmux example service"))
	})
	samlservice := samlmux.NewServiceProviderWithOption(
		&samlmux.ServiceProviderOptions{
			ServiceRunsAt: "https://localhost:3000",
			SsoPath:       "/saml/sso",
			AcsPath:       "/saml/acs",
			SloPath:       "/saml/slo",
			Cert:          &c,
			IdpMetadata:   idpMetaDataFromFile(),
			Logger:        log.Default(),
		},
	)

	if err != nil {
		panic(err)
	}
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
	fmt.Printf("login at %v%v", addressOfOurService, loginPath)
	http.ListenAndServeTLS(":3000", "./example.cert", "./example.key", samlservice)
}
