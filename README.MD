# nhs-login-java-example

This repo contains a sample application of how to connect to NHS login using spring security and MITREid client.

## Prerequisites:

 - Java 8
 - Maven
 - Generated keypair in Jwks format (https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server/wiki/Key-generation)
 - Access to NHS login sandpit

## Getting started:

Add your client details to application.properties

**application.properties**
```
oidc.issuer = https://auth.sandpit.signin.nhs.uk
oidc.clientid = Your client-id
oidc.scopes = openid profile
oidc.redirecturi = http://localhost:8080/openid_connect_login
oidc.keystorepath = keystore.jwks
oidc.defaultkey = Your kid for jwks
```

Add jwk key to keystore.jwks

To run the sample, run the following command in the root of the project.
```
    ./mvnw spring-boot:run
```

## Note:
> This application is provided as a demo to get started integrating with NHS login and shouldn't be deployed into a production environment :)