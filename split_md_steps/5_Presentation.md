## Presentation

This is the most important perspective to examine within our codelab. Here we will demonstrate how a credential holder can securely convey their alumni status without disclosing the actual signature of the degree they obtained. 

NOTE: This functionality just scratches the surface of what zero-knowledge proofs can achieve.  In a deeper dive, we could use zero-knowledge to produce a proof that a person obtained a degree from a Tier 1 university, but not disclose which one.

While the previous and next sections use local Golang code to perform their portions, the credential holder generally has much more limited compute.
After all, in our example, the holder may be using a mobile app to interact with the verifier in order to purchase something from their store.  Sindri's zero-knowledge proving API and infrastructure automation suite, powered by Google's reliable cloud, supply a necessary piece of the puzzle in order to make verifiable presentations a mainstream technology.

In the following codeblock, we will obtain a copy of the "degree verifier" circuit from Sindri's public circuit repository.  A circuit in a ZK context is a mathematical representation of the computation being proven.  We will then compile the circuit in order to prepare for the next phase, which produces the zero-knowledge proof.
```
sindri clone 21d6f894-4584-4515-a938-e1783a945d30 ./holder
cd holder
sindri deploy
```
If you inspect the `./holder` directory, you can find the code for the zero-knowledge program that will certify the BLS signature that was issued in the last step is valid.  Specifically this function within `holder/circuit.go` is worth special attention:
```
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
```
This is a zero-knowledge circuit definition written in [gnark](https://docs.gnark.consensys.io/overview).  It is performing the pairing check described in the previous section (`e(Sig ,G2)=e(Hm,Pk)`).  It will only produce a valid output if a user supplies `Sig`, `Hm`, `G2`, and `Pk` satisfy a special arithmetic relationship (one that is difficult to forge unless you have the secret key underlying the public key `Pk`.)

Since the credential holder in our example was issued the four necessary values in the previous step inside of their credentials, we can use those to request a proof from Sindri's API.
```
sindri proof create -i credential.json > credential-proof.json 
```
The code block above created a proof that the user has a signed piece of data corresponding to the university's public key `pk`.  If you inspect the `credential-proof.json` file that was produced, you'll notice that the `Sig` field is empty.  This is the major development that zero-knowledge has enabled.  In the next step, our verifier will be able to take the `credential-proof.json` file and convince themselves that the user has a signed degree, even if they withhold the signature itself.


---
SINDRI DRAFT NOTE: alter the circuit id above with finished version of sindri/verifiable-credential project once we publish
