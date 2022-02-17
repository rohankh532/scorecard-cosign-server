// Sample run-helloworld is a minimal Cloud Run service.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/google/go-github/v42/github"
	"github.com/gorilla/mux"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Scorecard signature certificate verification")
}

func verifySignature(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	reqBody, _ := ioutil.ReadAll(r.Body)

	// Get most recent Rekor entry uuid.
	rekorClient, _ := rekor.NewClient("https://rekor.sigstore.dev")
	uuids, _ := cosign.FindTLogEntriesByPayload(ctx, rekorClient, reqBody)
	entry, _ := cosign.GetTlogEntry(ctx, rekorClient, uuids[len(uuids)-1])
	fmt.Println("UUID List: ", uuids)

	// Extract certificate and get repo reference & path.
	certs, _ := extractCerts(entry)
	cert := certs[0]
	var repoRef string
	var repoPath string
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.6" {
			repoRef = string(ext.Value)
		}
		if ext.Id.String() == "1.3.6.1.4.1.57264.1.5" {
			repoPath = string(ext.Value)
		}
	}

	// Split repo path into owner and repo name
	ownerName := repoPath[:strings.Index(repoPath, "/")]
	repoName := repoPath[strings.Index(repoPath, "/")+1:]

	// Get workflow file from repo reference
	client := github.NewClient(nil)
	opts := &github.RepositoryContentGetOptions{Ref: repoRef}
	contents, _, _, _ := client.Repositories.GetContents(ctx, ownerName, repoName, ".github/workflows/scorecards.yml", opts)
	fmt.Println("Workflow contents: ", contents)

	// Next steps: verify workflow contents
}

// TODO: get this to import correctly.
func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", homePage)
	myRouter.HandleFunc("/projects/", verifySignature).Methods("POST")
	log.Fatal(http.ListenAndServe(":8080", myRouter))
}

func main() {
	log.Print("starting server...")

	handleRequests()
}
