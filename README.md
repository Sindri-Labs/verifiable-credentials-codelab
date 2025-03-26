# Verifiable Credentials and Zero Knowledge

This project explores the use of zero knowledge proofs with verifiable credentials, a new standardized form of digital credential offering several advantages over traditional credentials.

You can now work through a codelab based on this project, called
[Leveraging Verifiable Credentials and Zero-Knowledge Proofs with Sindri](https://www.cloudskillsboost.google/focuses/118451?parent=catalog&qlcampaign=1k-sindri-25), with associated gnark
[circuit](https://sindri.app/z/gcp-codelab/bls-verify/).
The codelab can also be found on [Google's Web3 Portal](https://cloud.google.com/application/web3/learn).

In the codelab, you work through a scenario in which a graduate proves to a third party that they received a signed degree credential from a particular institution, without revealing the signature or any other information about them or their degree. In the terminology of verifiable credentials, this is producing a verifiable presentation of a credential.

## Issuer and Verifier

This repository contains [Go](https://go.dev) code implementing the operations of a verifiable credential issuer and verifier. The issuer first generates a signed credential. The credential holder can then use the associated [circuit](https://sindri.app/z/gcp-codelab/bls-verify/) to generate a proof of signature, and incorporate it into a verifiable presentation. The verifier can be run by any party to verify this proof.
