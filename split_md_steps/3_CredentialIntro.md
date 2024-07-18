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
