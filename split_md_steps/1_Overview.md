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
