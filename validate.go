package main

import (
	"encoding/json"
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)
func parsePublicKey(pemEncoded string) (*jwt.PublicKey, error) {
    publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(pemEncoded))
    if err != nil {
        return nil, err
    }
    return publicKey, nil
}

func validate(payload []byte) ([]byte, error) {
	// Create a ValidationRequest instance from the incoming payload
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	settings, err := NewSettingsFromValidationReq(validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(400))
	}

	data := gjson.GetBytes(
		payload,
		"request.object.metadata.annotations")

	annotations := mapset.NewThreadUnsafeSet[string]()

	const publicKeyPEM = `      -----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF5/niXFLraxfyQWi5d43p0oyyJPM
	PoEygPHn86mdWdJFO8pcGAFSBk8Sh0d5OHL0QbZFbStzp1cU/Zjj1MNdtA==
	-----END PUBLIC KEY-----`

	data.ForEach(func(key, value gjson.Result) bool {
		annotation := key.String()
		annotations.Add(annotation)

		if settings.DeniedAnnotations.Contains(annotation) {
			deniedAnnotationsViolations = append(deniedAnnotationsViolations, annotation)
			return true
		}

		// Inside your data.ForEach loop where you iterate over annotations
    	// Let's assume the JWT is stored in an annotation named "encrypted.jwt"
		if annotation == "ncp.hyland.com/opa-exemption/jwt" {
			publicKey, err := parsePublicKey(publicKeyPEM)
			if err != nil {
				// Handle error
				return false 
			}
		

		
			if err != nil || !token.Valid {
				// JWT is invalid or there was an error parsing it
				return false //kubewarden.RejectRequest(
					//kubewarden.Message("Invalid JWT token"),
					//kubewarden.NoCode)
			}		
		}

		return true//this is the default true, if we have made it here, its a valid JWT
	})

	errorMsgs := []string{}

	if len(errorMsgs) > 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message(strings.Join(errorMsgs, ". ")),
			kubewarden.NoCode)
	}

	return kubewarden.AcceptRequest()
}
