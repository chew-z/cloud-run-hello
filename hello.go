// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc"
)

const (
	googleRootCertURL = "https://www.googleapis.com/oauth2/v3/certs"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Hello from Cloud Run! The container started successfully and is listening for HTTP requests on %s.", port)

	ctx := context.Background()
	projectID := getProjectID()
	log.Printf("GOOGLE_PROJECT_ID: %s", projectID)
	audience := "http://www.example.com"

	token := getJWToken(audience)
	if token != "" {
		verified, err := verifyGoogleIDToken(ctx, audience, token)
		if err != nil {
			log.Panic(err)
		}
		log.Printf("Verify %v", verified)
	}
	u := "https://example.com"
	makeAuthenticatedRequest(token, u)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hi there, I love %s!", "Cloud Run")
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

// Get project ID from metadata server
func getProjectID() string {
	const meta = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
	projectID := "???"
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	req, _ := http.NewRequest("GET", meta, nil)
	req.Header.Set("Metadata-Flavor", "Google")
	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		responseBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatal(err)
		}
		projectID = string(responseBody)
	}
	return projectID
}

// Check for network egress configuration (CR-GKE)
func checkNet() bool {
	networkEgressError := false
	projectID := getProjectID()
	if projectID != "???" {
		client := &http.Client{
			Timeout: 3 * time.Second,
		}
		// Check to see if we can reach something off the cluster e.g. www.google.com
		req, _ := http.NewRequest("HEAD", "https://www.google.com", nil)
		res, err := client.Do(req)
		if err == nil && res.StatusCode >= 200 && res.StatusCode <= 299 {
			// egress worked successfully
			log.Print("Verified that network egress is working as expected.")
		} else {
			log.Print("Network egress appears to be blocked. Unable to access https://www.google.com.")
			networkEgressError = true
		}
	}
	return networkEgressError

}

func getJWToken(audience string) string {
	const meta = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience="
	jwToken := ""
	auURL := fmt.Sprintf("%s%s", meta, audience)
	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	req, err := http.NewRequest("GET", auURL, nil)
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return jwToken
	}
	// convert response.Body to text
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		log.Println(err.Error())
		return jwToken
	}
	jwToken = string(bodyBytes)
	return jwToken
}

func verifyGoogleIDToken(ctx context.Context, aud string, token string) (bool, error) {
	keySet := oidc.NewRemoteKeySet(ctx, googleRootCertURL)
	// https://github.com/coreos/go-oidc/blob/master/verify.go#L36
	var config = &oidc.Config{
		SkipClientIDCheck: false,
		ClientID:          aud,
	}
	verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)
	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return false, err
	}
	log.Printf("Verified id_token with Issuer %v: ", idt.Issuer)
	return true, nil
}

func makeAuthenticatedRequest(idToken string, url string) {

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("content-type", "application/json")
	req.Header.Add("Authorization", "Bearer "+idToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	bodyString := string(bodyBytes)
	log.Printf("Authenticated Response: %v", bodyString)
}
