package circuit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	bls12377 "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

type Circuit struct {
	// Your circuit inputs go here.
	Sig bls12377.G1Affine
	G2  bls12377.G2Affine `gnark:",public"`
	Hm  bls12377.G1Affine `gnark:",public"`
	Pk  bls12377.G2Affine `gnark:",public"`
}

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

// Common utility for reading JSON in from a file.
func ReadFromInputPath(pathInput string) (map[string]interface{}, error) {

	absPath, err := filepath.Abs(pathInput)
	if err != nil {
		fmt.Println("Error constructing absolute path:", err)
		return nil, err
	}

	file, err := os.Open(absPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var data map[string]interface{}
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		panic(err)
	}

	return data, nil
}

// Construct a witness from input data in a JSON file.
func FromJson(pathInput string) witness.Witness {

	data, err := ReadFromInputPath(pathInput)
	if err != nil {
		panic(err)
	}

	// Extract individual JSON fields, making sure they are themselves maps
	var jSig map[string]interface{} = data["Sig"].(map[string]interface{})
	var jG2  map[string]interface{} = data["G2" ].(map[string]interface{})
	var jG2X map[string]interface{} = jG2 ["X"  ].(map[string]interface{})
	var jG2Y map[string]interface{} = jG2 ["Y"  ].(map[string]interface{})
	var jHm  map[string]interface{} = data["Hm" ].(map[string]interface{})
	var jPk  map[string]interface{} = data["Pk" ].(map[string]interface{})
	var jPkX map[string]interface{} = jPk ["X"  ].(map[string]interface{})
	var jPkY map[string]interface{} = jPk ["Y"  ].(map[string]interface{})

	// Now initialize circuit input field elements from the JSON data
	var Sig bls12377.G1Affine = bls12377.G1Affine{ X:frontend.Variable(jSig["X"]), Y:frontend.Variable(jSig["Y"]) }
	var G2 bls12377.G2Affine;
	G2.P.X = fields_bls12377.E2{ A0: frontend.Variable(jG2X["A0"]), A1: frontend.Variable(jG2X["A1"]) }
	G2.P.Y = fields_bls12377.E2{ A0: frontend.Variable(jG2Y["A0"]), A1: frontend.Variable(jG2Y["A1"]) }
	var Hm bls12377.G1Affine = bls12377.G1Affine{ X:frontend.Variable(jHm["X"]), Y:frontend.Variable(jHm["Y"]) }
	var Pk bls12377.G2Affine;
	Pk.P.X = fields_bls12377.E2{ A0: frontend.Variable(jPkX["A0"]), A1: frontend.Variable(jPkX["A1"]) }
	Pk.P.Y = fields_bls12377.E2{ A0: frontend.Variable(jPkY["A0"]), A1: frontend.Variable(jPkY["A1"]) }

	// Construct the witness
	assignment := Circuit{
		Sig: Sig,
		G2:  G2,
		Hm:  Hm,
		Pk:  Pk,
	}

	w, err := frontend.NewWitness(&assignment, ecc.BW6_761.ScalarField())
	if err != nil {
		panic(err)
	}
	return w
}
