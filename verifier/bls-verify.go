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

	var pinned_vk string = "" +
		"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"

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
