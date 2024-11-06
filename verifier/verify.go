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
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
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

// This defines the public and private inputs to the circuit
type Circuit struct {
	// Your circuit inputs go here.
	Sig bls12377.G1Affine
	G2  bls12377.G2Affine `gnark:",public"`
	Hm  bls12377.G1Affine `gnark:",public"`
	Pk  bls12377.G2Affine `gnark:",public"`
}

// This specifies what the circuit is intended to verify
func (circuit *Circuit) Define(api frontend.API) error {
	// performs the Miller loops
	ml, _ := bls12377.MillerLoop(api, []bls12377.G1Affine{circuit.Sig, circuit.Hm}, []bls12377.G2Affine{circuit.G2, circuit.Pk})
	var one fields_bls12377.E12
	one.SetOne()

	// performs the final expo
	e := bls12377.FinalExponentiation(api, ml)
	e.AssertIsEqual(api, one)

	return nil
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
	schema, err := frontend.NewSchema(&Circuit{})
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
