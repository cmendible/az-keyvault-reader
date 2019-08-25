package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/gorilla/mux"
)

func getKeyVaultSecret(w http.ResponseWriter, r *http.Request) {
	// Get the Key Vault name from the Environment
	keyvaultName := os.Getenv("AZURE_KEYVAULT_NAME")
	keyvaultEndpoint := fmt.Sprintf("https://%s.vault.azure.net", keyvaultName)

	// Read variables form the request Url
	params := mux.Vars(r)
	keyvaultSecretName := params["secret_name"]
	keyvaultSecretVersion := params["secret_version"]

	// Create the key vault client & authorizer
	keyVaultClient := keyvault.New()
	authorizer, err := auth.NewAuthorizerFromEnvironment()

	if err == nil {
		keyVaultClient.Authorizer = authorizer
	}

	log.Printf("reading secret %s with version %s", keyvaultSecretName, keyvaultSecretVersion)

	// Get and return the secret
	secret, err := keyVaultClient.GetSecret(context.Background(), keyvaultEndpoint, keyvaultSecretName, keyvaultSecretVersion)
	if err != nil {
		log.Printf("failed to retrieve the Keyvault secret: %v", err)
		http.Error(w, "failed to retrieve the Keyvault secret", http.StatusInternalServerError)
		return
	}

	js, err := json.Marshal(*secret.Value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(js)

	log.Printf("secret %s with version %s was found and returned", keyvaultSecretName, keyvaultSecretVersion)
}

func main() {
	log.Print("az-keyvault-reader is starting...")

	// Create a route with the secret_name & secret_version variables
	rtr := mux.NewRouter()
	rtr.HandleFunc("/secrets/{secret_name:[A-Za-z0-9-]+}/{secret_version:[A-Za-z0-9]+}", getKeyVaultSecret).Methods("GET")

	http.Handle("/", rtr)
	http.ListenAndServe(":8333", nil)
	log.Println("az-keyvault-reader server listening on :8333")
}
