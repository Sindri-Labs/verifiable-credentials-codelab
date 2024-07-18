## Presentation

This is the most important perspective to examine within our codelab.
Here we will demonstrate how a credential holder can securely convey identity.


While the previous and next sections use local Golang code to perform their portions, the credential holder generally has much more limited compute.
After all, in our example the holder is using a mobile app to interact with the verifier.
For this reason Sindri + GCP makes sense...

```
sindri clone 21d6f894-4584-4515-a938-e1783a945d30 ./holder
cd holder
sindri deploy
sindri proof create -i credential.json > credential-proof.json 
```

!! alter circuit id above with finished version of sindri/verifiable-credential project !!
