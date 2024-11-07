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

	// The verification key for circuit ID 42543290-0746-48d5-998a-e39197e5cf79:
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
