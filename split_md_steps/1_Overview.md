## Overview

Verifiable credentials are a new form of digital credential that offers more flexibility in authentication and authorization. They allow for proving the existence and properties of signed statements without revealing unnecessary personal information.

In this lab, you'll learn about verifiable credentials and how to build credential schemes using zero-knowledge proofs. This cryptographic technique is core to our ability to prove the validity of a statement without revealing the underlying data. We'll use the serverless infrastructure of Sindri, which leverages Google Cloud Platform, to automate and accelerate the process of generating zero-knowledge proofs.

In particular, we will focus on a practical application of the verifiable credential ecosystem and the cryptographic mechanisms underlying the three primary roles: the issuer, the holder, and the verifier.

To illustrate these concepts, we'll use a university-issued degree credential as our primary example throughout this codelab where a university (the issuer) awards a comprehensive credential to a graduate (the holder). This credential contains detailed information about the graduate. However, when the graduate seeks to leverage this credential to claim an alumni discount on merchandise, they may prefer not to disclose all the information associated with the credential to the vendor (the verifier). With verifiable credentials powered by zero-knowledge proofs, we will walk through the machinery that lets a degree holder share an anonymized but tamper-resistant proof of their claim.

![Verifiable Credential Lifecycle](./vc-lifecycle.png)

NOTE: The bottom component, i.e. the registry, is generally managed by a secure ledger or blockchain.

### What you'll learn

- What verifiable credentials are and how they differ from traditional credentials
- How issuers produce these digital credentials
- How a verifiable credential is transformed into a verifiable presentation via zero-knowledge proofs
- How to verify the presentation

### Prerequisites

- Basic understanding of cryptography concepts
- Familiarity with JSON and command-line interfaces
