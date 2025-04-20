package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

// RecaptchaResponse represents the response from Google's reCAPTCHA verification API
type RecaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// VerifyCaptcha verifies a reCAPTCHA response token
func VerifyCaptcha(recaptchaResponse string) (bool, error) {
	// Get reCAPTCHA secret key from environment variable
	secretKey := os.Getenv("RECAPTCHA_SECRET_KEY")
	if secretKey == "" {
		// Use a default key for development (this should be changed in production)
		secretKey = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe" // Google's test key
	}

	// Make a POST request to Google's reCAPTCHA verification API
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {secretKey},
		"response": {recaptchaResponse},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// Parse the JSON response
	var recaptchaResp RecaptchaResponse
	err = json.Unmarshal(body, &recaptchaResp)
	if err != nil {
		return false, err
	}

	// Return the verification result
	return recaptchaResp.Success, nil
}

// CaptchaHandler is no longer needed as we're using Google reCAPTCHA
// This is just a placeholder to maintain API compatibility
func CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	// Return a simple message indicating that we're using Google reCAPTCHA now
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "This endpoint is no longer used. We've switched to Google reCAPTCHA."}`))
}
