package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/microcontroller/vc-sindri-app/bls-verify/circuit"
)

type ProofDetailResponse struct {
	Proof           Proof           `json:"proof"`
	VerificationKey VerificationKey `json:"verification_key"`
	PublicInputJson json.RawMessage `json:"public"`
}

type Proof struct {
	EncodedProof string `json:"proof"`
}

type VerificationKey struct {
	EncodedVerifyingKey string `json:"verifying_key"`
}

func exitOnError(err error, action string) {
	if err != nil {
		fmt.Printf("Error %s: %v\n", action, err)
		os.Exit(1)
	}
}

func main() {
	// Parse the necessary data from proof detail response JSON.
	var proofDetailResponse ProofDetailResponse
	if len(os.Args) < 2 {
		fmt.Println("Please provide the path to the proof detail JSON file as an argument.")
		return
	}
	var pinned_vk string = "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"
	if len(os.Args) > 2 {
		pinned_vk = os.Args[2]
	}
	filename := os.Args[1]
	data, err := os.ReadFile(filename)
	exitOnError(err, "reading file")
	err = json.Unmarshal(data, &proofDetailResponse)
	exitOnError(err, "unmarshalling JSON")

	// Load in the proof.
	decodedProof, err := base64.StdEncoding.DecodeString(proofDetailResponse.Proof.EncodedProof)
	exitOnError(err, "decoding proof")
	proof := groth16.NewProof(ecc.BW6_761)
	_, err = proof.ReadFrom(bytes.NewReader(decodedProof))
	exitOnError(err, "reading proof")

	// Test the verification key against the pinned one
	if proofDetailResponse.VerificationKey.EncodedVerifyingKey != pinned_vk {
		fmt.Println("Verification key does not match the pinned one.")
		os.Exit(1)
	}
	// Load in the verifying key.
	decodedVerifyingKey, err := base64.StdEncoding.DecodeString(proofDetailResponse.VerificationKey.EncodedVerifyingKey)
	exitOnError(err, "decoding verifying key")
	verifyingKey := groth16.NewVerifyingKey(ecc.BW6_761)
	_, err = verifyingKey.ReadFrom(bytes.NewReader(decodedVerifyingKey))
	exitOnError(err, "reading verifying key")

	// Construct the witness based on the public inputs.
	schema, err := frontend.NewSchema(&circuit.Circuit{})
	exitOnError(err, "constructing schema")
	publicWitness, err := witness.New(ecc.BW6_761.ScalarField())
	exitOnError(err, "constructing witness")
	err = publicWitness.FromJSON(schema, proofDetailResponse.PublicInputJson)
	exitOnError(err, "parsing public inputs")

	// Verify the proof.
	err = groth16.Verify(proof, verifyingKey, publicWitness)
	exitOnError(err, "verifying proof")
	fmt.Println("Proof verified successfully.")
}
