github-token-proxy
---

Work In Progress

[GitHub Apps installation token](https://docs.github.com/en/rest/apps/installations?apiVersion=2022-11-28) proxy


### Server
The server performs JWT authentication and retrieves tokens from GitHub Apps.

### Client
The client component is further divided into two tasks:

**Creation of JWT**: The client generates JWTs (JSON Web Tokens) for authentication purposes.

**Token retrieval**: The client obtains tokens from the server and acts as a Git Credential Helper.

[Git Credential Helper](https://git-scm.com/docs/gitcredentials) functionality allows the client to assist Git in handling authentication.

### Configuration


Git Credential Helper does not have an easy way to automatically detect the remote Organization and Repository of your own repository.

Therefore, you need to configure it separately for each remote, which means you need to write configurations for each remote you have.

```
[credential "https://github.com/atpons/github-token-proxy"]
        helper = !/path/to/github-token-proxy-helper -org=atpons -repo=github-token-proxy
        UseHttpPath = true
```

### Why JWT?

We utilize JWT as an authentication backend to enable seamless utilization of SSH keys present on each machine.

The private key is supported in PEM format, while the public key is expected to be in a format recognized by OpenSSH.

By using this approach, we can seamlessly integrate the existing SSH workflows for authentication purposes.