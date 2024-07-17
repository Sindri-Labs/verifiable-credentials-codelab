# Building Verifiable Credentials Using Zero Knowledge Proofs

## Overview

In this lab, you'll learn about verifiable credentials and how to build credential schemes using zero knowledge proofs. We'll use the serverless infrastructure of Sindri, which leverages Google Cloud Platform, to automate and accelerate the process of generating zero knowledge proofs.

Verifiable credentials are a new form of digital credential that offers more flexibility in authentication and authorization. They allow for proving the existence and properties of signed statements without revealing unnecessary personal information.

We'll be using the Gnark framework from Consensys to produce Groth16 proofs, which minimize proof sizes and verifier work, making them particularly attractive for Web3 applications.

## What you'll learn

- What verifiable credentials are and how they differ from traditional credentials
- How to construct a verifiable credential using BLS signatures
- How to generate zero knowledge proofs for credential verification
- How to verify zero knowledge proofs for credentials

## Prerequisites

- Basic understanding of cryptography concepts
- Familiarity with JSON and command-line interfaces
- A Sindri account (free to create for new users [here](link))

## Setup and requirements

1. Install Node.js v18 or later
2. Obtain Sindri API key from [here](link)
3. Install the Sindri CLI and login:

```bash
# Install or update the Sindri CLI to the latest version.
$ npm install -g sindri@latest

# Check that the Sindri CLI is installed and using the latest version.
$ sindri --version
v0.0.1-alpha.49

# First-time user: authenticate to generate an API key
$ sindri login
? Username: <your_username>
? Password: <your_password>
? New API Key Name: (machinename-sdk)
```

## Task 1. Understanding Verifiable Credentials

Verifiable credentials are a standardized way of expressing credentials in the digital world. They offer several advantages over traditional credentials:

1. They can incorporate multiple signed statements from various authorities.
2. They allow proving properties of credentials without revealing all information.
3. They can use verifiable data registries for increased accessibility and security.

We will be building verifiable credentials in [JSON-LD](https://json-ld.org), a flexible lightweight format for linking data. Here is [an example credential from W3C](https://github.com/w3c/vc-test-suite/blob/gh-pages/test/vc-data-model-1.0/input/example-009.jsonld):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "credentialSchema": {
    "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
    "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
  },
  "issuer": "did:example:Wz4eUg7SetGfaUVCn8U9d62oDYrUJLuUtcy619",
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "givenName": "Jane",
    "familyName": "Doe",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science in Mechanical Engineering",
      "college": "College of Engineering"
    }
  },
  "proof": {
    "type": "CLSignature2019",
    "issuerData": "5NQ4TgzNfSQxoLzf2d5AV3JNiCdMaTgm...BXiX5UggB381QU7ZCgqWivUmy4D",
    "attributes": "pPYmqDvwwWBDPNykXVrBtKdsJDeZUGFA...tTERiLqsZ5oxCoCSodPQaggkDJy",
    "signature": "8eGWSiTiWtEA8WnBwX4T259STpxpRKuk...kpFnikqqSP3GMW7mVxC4chxFhVs",
    "signatureCorrectnessProof": "SNQbW3u1QV5q89qhxA1xyVqFa6jCrKwv...dsRypyuGGK3RhhBUvH1tPEL8orH"
  }
}
```

As you can see, the credential itself is JSON document - a tree of key-value pairs - and quite unlike X.509 it is both human-readable and machine-parsable. One important aspect of verifiable credentials is the ability to build a verifiable presentation rather than just passing along the credential itself. This is the key innovation that makes verifiable credentials so flexible. Here is W3C's [example verifiable presentation](https://github.com/w3c/vc-test-suite/blob/gh-pages/test/vc-data-model-1.0/input/example-015-zkp-vp.jsonld) for the above credential:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": "VerifiablePresentation",
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "credentialSchema": {
      "id": "did:example:cdf:35LB7w9ueWbagPL94T9bMLtyXDj9pX5o",
      "type": "did:example:schema:22KpkXgecryx9k7N6XN1QoN3gXwBkSU8SfyyYQG"
    },
    "issuer": "did:example:Wz4eUg7SetGfaUVCn8U9d62oDYrUJLuUtcy619",
    "issuanceDate": "2010-01-01T19:23:24Z",
    "credentialSubject": {
      "degreeType": "BachelorDegree",
      "degreeSchool": "College of Engineering"
    },
    "proof": {
      "type": "ex:AnonCredDerivedCredentialv1",
      "primaryProof": "cg7wLNSi48K5qNyAVMwdYqVHSMv1Ur8i...Fg2ZvWF6zGvcSAsym2sgSk737",
      "nonRevocationProof": "mu6fg24MfJPU1HvSXsf3ybzKARib4WxG...RSce53M6UwQCxYshCuS3d2h"
    }
  },
  "proof": {
    "type": "ex:AnonCredPresentationProofv1",
    "proofValue": "DgYdYMUYHURJLD7xdnWRinqWCEY5u5fK...j915Lt3hMzLHoPiPQ9sSVfRrs1D"
  }
}
```

In the presentation, we include only the bare minimum necessary from the credential, along with a ZK proof. The credential holder can generate as many presentations as they wish - the holder may attempt to access some gated resource, and be given a presentation request requiring them to prove some set of specific properties. This example presentation shows how to embed a proof that the declared claims of `degreeType` and `degreeSchool` were signed by the issuer in the original credential, without revealing the original signature (to avoid it being used for tracking), or more fields than are required to gain access.

Other kinds of proof are possible within the verified credential framework, using general purpose ZK proofs. For instance, `predicate proofs` allow you to prove some property of a claim without revealing the claim itself - we could include a proof both that a claimed date of birth is signed and that it confirms the credential holder's age as least 18, all without actually revealing that date of birth.

## Task 2. Building a Credential Scheme with Zero Knowledge Proofs

Step 1: Clone the verified credential circuit from sindri

```bash
$ sindri clone sindri-vc-codelab
```

Step 2: Obtain the credential from the issuer

### What we're doing:

In our new verifiable credential scheme, we will include multiple claims about the credential holder, each of which is signed with a BLS signature. Rather than including this signature in presentations, each presentation will contain a proof that the BLS signatures in the credential are present and valid - all without revealing the signatures themselves.

When approaching verification, it is always prudent to ask "But how will the verifier know that?" We want the verifier to be sure that the credential holder has a valid credential, with an acceptable `degreeType` and a valid signature from a known issuer on the `degreeType` and `degreeSchool` properties.

To issue the credential, we will need a BLS key and the ability to generate BLS signatures. As mentioned earlier, we cannot yet rely on general tools like OpenSSL to implement all the crypto for us; having said that, there are code libraries available. For simplicity of exposition, here we will use a proving circuit from [Consensys](https://consensys.io) that is built into [Gnark playground](https://play.gnark.io), and issue credentials using the [gnark-crypto](https://pkg.go.dev/github.com/consensys/gnark-crypto) ecc module. We will also have the signing code read in an existing JSON document, add signatures and witnesses, and output the modified document - this leaves the problem of credential construction and schema compliance for another day, and we can just adapt W3C's examples for our own use.

When considering **any** cryptographic scheme, it is well worth examining which items of data are share with whom, and for what purpose. In our case, we will issue an initial credential that contains signatures on particular fields - this could be used as-is, if you trust the recipient to not be automatically harvesting data. We will substitute a zero knowledge proof of the correctness of each signature, so that the verifier sees only the fields we wish to share, and does not see the raw signature. To generate those proofs, we need to supply Sindri with the raw signature and the hash of the field being shared, but Sindri does not need to see the data that was signed. This separation helps to ensure that Sindri is a purely disinterested third party.
