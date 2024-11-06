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
