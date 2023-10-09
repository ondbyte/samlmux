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
	idpMetaData, err := samlmux.NewMetDataFromFile("./idp_metadata.xml")
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
	samlservice, err := samlmux.NewServiceProvider(
		addressOfOurService,
		fmt.Sprintf("%v%v", addressOfOurService, acsPath),
		fmt.Sprintf("%v%v", addressOfOurService, logoutPath),
		&c,
		samlTestIdMetaData(),
		onAuthFlowDone,
		log.Default(),
	)

	if err != nil {
		panic(err)
	}
	// write our metadata to a file
	mdStr, err := samlservice.MetadataStr()
	if err != nil {
		panic(err)
	}

	file, err := os.Create("./our_metadata.xml")
	if err != nil {
		panic(err)
	}
	_, err = file.Write([]byte(mdStr))
	if err != nil {
		panic(err)
	}
	file.Close()
	mux := http.DefaultServeMux
	mux.HandleFunc(metaDataPath, func(w http.ResponseWriter, r *http.Request) {
		samlservice.HandleMetaData(w, r)
	})
	mux.HandleFunc(acsPath, func(w http.ResponseWriter, r *http.Request) {
		samlservice.HandleAcs(w, r)
	})

	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		samlservice.HandleSamlAuth(w, r)
	})
	http.ListenAndServeTLS(":3000", "./example.cert", "./example.key", mux)
}
