# SAML 2.0 sandbox on java

Experiments with implementing SAML 2.0 SP on Java using Spring Boot and [OneLogin java-saml library](https://github.com/onelogin/java-saml)

## Cert/Key generate
`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`

## SAML IdPs
Tested with [SAMLTestID](https://samltest.id/) and [OneLogin](https://www.onelogin.com/)