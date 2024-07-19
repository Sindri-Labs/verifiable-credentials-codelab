## Issuance

In this section, we will be signing a verifiable credential document as an issuer.  

Recall that a university will transfer a verifiable credential to a holder that certifies the owner of this credential attained a degree.  So, we will start with this claim (`issuer/credential.json`) and add our signature using the private key of the university (`issuer/issuer_sk.txt`).
```bash
{
  "credentialSubject": {
    "degreeType": "BachelorDegree"
  }
}
```

To do so, run the following commands:
```bash
cd issuer
go run issuer.go issuer_sk.txt credential.json
```
The output should indicate that you have produced a file called `credential-signed.json` which has added some new fields to `credential.json`. Namely, you should see the following values inside the "witnesses" section: `G2`, `Hm`, `Pk`, and `Sig`.  These are all the key fields required in the [BLS Signature Scheme](https://en.wikipedia.org/wiki/BLS_digital_signature).

* `G2` is the public generator of an elliptic curve group,
* `Hm` is the hash of the message (the credential contents),
* `Pk` is the public key of the issuer (the university),
* `Sig` is the signature, or `Hm` exponentiated by the issuer's private key

The key relationship these values satisfy is:
```
e(Sig ,G2)=e(Hm,Pk). 
```
where `e` is a special operation related to [elliptic curve pairing](https://medium.com/@VitalikButerin/exploring-elliptic-curve-pairings-c73c1864e627).  
