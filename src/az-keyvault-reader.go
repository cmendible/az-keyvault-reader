package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/keyvault"
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

	// Create the key vault client & authorizer
	keyVaultClient := keyvault.New()
	authorizer, err := auth.NewAuthorizerFromEnvironment()

	if err == nil {
		keyVaultClient.Authorizer = authorizer
	}

	log.Printf("reading secret %s", keyvaultSecretName)

	// Get and return the secret
	secret, err := keyVaultClient.GetSecret(context.Background(), keyvaultEndpoint, keyvaultSecretName, "")
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

	log.Printf("secret %s was found and returned", keyvaultSecretName)
}

type ipFilterMiddleware struct {
	next http.Handler
}

func wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{next: next}
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	allowed := false
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteIP == "::1" || remoteIP == "127.0.0.1" {
		allowed = true
	}
	if !allowed {
		//show simple forbidden text
		log.Printf("blocked %s", remoteIP)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}

func main() {
	log.Print("az-keyvault-reader is starting...")

	// Create a route with the secret_name & secret_version variables
	rtr := mux.NewRouter()
	rtr.HandleFunc("/secrets/{secret_name:[A-Za-z0-9-]+}/", getKeyVaultSecret).Methods("GET")
	rtr.HandleFunc("/secrets/{secret_name:[A-Za-z0-9-]+}/{secret_version:[A-Za-z0-9]+}", getKeyVaultSecret).Methods("GET")

	// Protect the router
	protectedHandler := wrap(rtr)

	srv := &http.Server{
		Addr:    ":8333",
		Handler: protectedHandler,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("Failed to listen and serve az-keyvault-reader: %v", err)
		}
	}()

	log.Println("az-keyvault-reader serve listening on port 8333")

	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	log.Printf("Got OS shutdown signal, shutting down az-keyvault-reader gracefully...")
	srv.Shutdown(context.Background())
}
