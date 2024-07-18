## Setup and requirements

Following the lifecycle of a verifiable credential, we will use Golang programs to simulate how issuers and verifiers accomplish their tasks and we will use Sindri, running on GCP, to perform the tasks of a credential holder and presenter.

In order to carry out these steps, you'll need to install the following:

1. [Install Golang](https://go.dev/doc/install)
2. [Install Node.js v18 or later](https://nodejs.org/en/download/package-manager)
3. Obtain Sindri account from [here](https://sindri.app/signup/)
4. Install the [Sindri CLI](https://sindri.app/docs/getting-started/cli/) and login:

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
