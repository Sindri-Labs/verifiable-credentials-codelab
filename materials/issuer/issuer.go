package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

func exitOnError(err error, action string) {
	if err != nil {
		fmt.Printf("Error %s: %v\n", action, err)
		os.Exit(1)
	}
}

var g1Gen bls12377.G1Affine
var g2Gen bls12377.G2Affine

func bls_sign(sk *big.Int, msg []byte) (*bls12377.G1Affine, bls12377.G1Affine, error) {
	hm, err := bls12377.HashToG1(msg, nil)
	exitOnError(err, "hashing message to G1")
	sig := new(bls12377.G1Affine).ScalarMultiplication(&hm, sk)

	// Negate the signature more efficient verification
	sig.Y.Neg(&sig.Y)
	return sig, hm, nil
}

func bls_verify(pk *bls12377.G2Affine, msg []byte, sig *bls12377.G1Affine) (bool, error) {
	hm, err := bls12377.HashToG1(msg, nil)
	exitOnError(err, "hashing message to G1")
	ml, err := bls12377.MillerLoop([]bls12377.G1Affine{*sig, hm}, []bls12377.G2Affine{g2Gen, *pk})
	if err != nil {
		return false, err
	}
	e := bls12377.FinalExponentiation(&ml)
	if e.IsOne() {
		return true, nil
	}
	return false, nil
}

func getIssuerKey(issuerKeyPath string) (*big.Int, *bls12377.G2Affine, error) {
	// Load the issuer key file, or create if it does not exist
	_, err := os.Stat(issuerKeyPath)

	var sk1 []byte
	var sk  big.Int
	var pk  *bls12377.G2Affine

	if os.IsNotExist(err) {
		g2Order := fr.Modulus()
		fmt.Printf("Issuer key file %s does not exist, creating it\n", issuerKeyPath)
		// Create the issuer key file

		issuerKeyFile, err := os.Create(issuerKeyPath)
		if err != nil {
			return nil, nil, err
		}
		defer issuerKeyFile.Close()

		// Generate a new BLS key pair
		ski, err := rand.Int(rand.Reader, g2Order)
		if err != nil {
			return nil, nil, err
		}
		sk.Set(ski)
	
		pk = new(bls12377.G2Affine).ScalarMultiplicationBase(&sk)

		// Write the secret key to the issuer key file
		sk1 = []byte(sk.Text(16))
		_, err = issuerKeyFile.Write(sk1)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Read the issuer key file with readall
		sk1, err := os.ReadFile(issuerKeyPath)
		if err != nil {
			return nil, nil, err
		}

		// Unmarshall the private key
		sk.SetString(string(sk1), 16)

		// Get the public key from the secret key
		pk = new(bls12377.G2Affine).ScalarMultiplicationBase(&sk)
	}
	return &sk, pk, nil
}

func main() {

	argCount := len(os.Args[1:])

	if argCount != 2 {
		fmt.Println("Usage: issuer <issuer_key_file> <unsigned_credential_file>")
		os.Exit(1)
	}

	// Set up variables for later use
	unsignedCredentialPath := os.Args[2]
	_, _, g1Gen, g2Gen = bls12377.Generators()
	sk, pk, err := getIssuerKey(os.Args[1])
	exitOnError(err, "getting issuer key")

	// Read the unsigned credential file and parse as JSON
	unsignedCredentialData, err := os.ReadFile(unsignedCredentialPath)
	exitOnError(err, "reading unsigned credential file")
	var credential map[string]interface{}
	err = json.Unmarshal(unsignedCredentialData, &credential)
	exitOnError(err, "parsing unsigned credential JSON")

	// Extract verifiableCredential.credentialSubject from the JSON
	var json_vc  map[string]interface{} = credential["verifiableCredential"].(map[string]interface{})
	var json_sub map[string]interface{} = json_vc["credentialSubject"].(map[string]interface{})

	// Base64 encode the issuer public key
	var claim string = "did:example:ToyBLSIssuer"
	json_vc["issuer"] = claim
	json_vc["issuerPubKey"] = pk

	// Find or create the issuance date inside json_vc
	json_vc["issuanceDate"] = time.Now().Format(time.RFC3339)

	// Find or create the proof key inside json_vc
	var json_proof map[string]interface{}
	if _, ok := json_vc["proof"]; ok {
		json_proof = json_vc["proof"].(map[string]interface{})
	} else {
		json_proof = make(map[string]interface{})
		json_vc["proof"] = json_proof
	}

	// Find or create the witnesses key inside json_vc
	var json_witnesses map[string]interface{}
	if _, ok := json_vc["witnesses"]; ok {
		json_witnesses = json_vc["witnesses"].(map[string]interface{})
	} else {
		json_witnesses = make(map[string]interface{})
		json_vc["witnesses"] = json_witnesses
	}

	// One signature per field sure is one way to achieve selective disclosure
	// We don't expect anybody else to adopt this scheme, labeling it as a toy
	json_proof["type"] = "ToyBls12377Signature2020OnFields"

	// Iterate over the credential subject fields, signing each one
	for key, value := range json_sub {
 		// Sign a "key: value" statement with the issuer key
		msg := fmt.Sprintf("%s: %s", key, value)
		sig, hm, err := bls_sign(sk, []byte(msg))
		exitOnError(err, "signing credential field")
		fmt.Printf("Signature[%s]: %x\n", key, sig)
		var json_witness map[string]interface{}
		if _, ok := json_witnesses[key]; ok {
			json_witness = json_witnesses[key].(map[string]interface{})
		} else {
			json_witness = make(map[string]interface{})
			json_witnesses[key] = json_witness
		}
		
		// Marshal the G2 generator in a way we can read back in
		g2j  := make(map[string]interface{})
		g2jx := make(map[string]interface{})
		g2jy := make(map[string]interface{})
		g2j["X"]       = g2jx
		g2j["Y"]       = g2jy
		g2jx["A0"] = g2Gen.X.A0.String()
		g2jx["A1"] = g2Gen.X.A1.String()
		g2jy["A0"] = g2Gen.Y.A0.String()
		g2jy["A1"] = g2Gen.Y.A1.String()

		// Marshal the message hash in a way we can read back in
		hmj := make(map[string]interface{})
		hmj["X"] = hm.X.String()
		hmj["Y"] = hm.Y.String()
		
		// Load the witness object with the necessary components
		json_witness["Sig"] = sig
		json_witness["G2"]  = g2j
		json_witness["Hm"]  = hmj
		json_witness["Pk"]  = pk

		// Verify the signature, just to be sure
		res, err := bls_verify(pk, []byte(msg), sig)
		exitOnError(err, "verifying credential field")
		if !res {
			fmt.Printf("Signature[%s] NOT verified\n", key)
		}
	
		// Create a key under the proof object for the signature
		json_proof[key] = sig
	}

	// Write the signed credential to a new file at <credential>-signed.json
	// Trim the .json extension from the unsigned credential file name first
	unsignedCredentialName := unsignedCredentialPath[:len(unsignedCredentialPath)-5]
	signedCredentialPath := unsignedCredentialName + "-signed.json"
	signedCredentialFile, err := os.Create(signedCredentialPath)
	exitOnError(err, "creating signed credential file")
	defer signedCredentialFile.Close()

	// Write the signed credential to the file
	signedCredentialData, err := json.Marshal(credential)
	exitOnError(err, "marshalling signed credential JSON")
	_, err = signedCredentialFile.Write(signedCredentialData)
	exitOnError(err, "writing signed credential file")

	fmt.Printf("Signed credential written to %s\n", signedCredentialPath)
}