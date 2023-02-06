# mini-acme 

## 1 | ACME Protocol

Public Key Infrastructures (PKIs) using X.509 certificates are used for many purposes, the most significant of which is the authentication of domain names. Certificate Authorities (CAs) are trusted to verify that an applicant for a certificate legitimately represents the domain name(s) in the certificate. Traditionally, this verification is done through various ad-hoc methods.

The [Automatic Certificate Management Environment (ACME) protocol](https://tools.ietf.org/html/rfc8555) aims to facilitate the automation of certificate issuance by creating a standardized and machine-friendly protocol for certificate management.

More information about ACME and relevant background can be found in [RFC8555](https://tools.ietf.org/html/rfc8555).

## 3 |  Your Task

The task is to write an application that implements ACMEv2. However, to make the application self-contained and in order to facilitate testing, the application will need to have more functionality than a bare ACME client.

### 3.1 | Application Components

The application must consist of the following components:

- *ACME client:* An ACME client which can interact with a standard-conforming ACME server.
- *DNS server:* A DNS server which resolves the DNS queries of the ACME server.
- *Challenge HTTP server:* An HTTP server to respond to http-01 queries of the ACME server.
- *Certificate HTTPS server:* An HTTPS server which uses a certificate obtained by the ACME client.
- *Shutdown HTTP server:*  An HTTP server to receive a shutdown signal.

From Network Security Course @ ETH Zürich, Fall 2022