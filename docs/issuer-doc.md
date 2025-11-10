# IMMERSE Issuer: Implementation Guidelines

## Table of Contents

- [IMMERSE Issuer: Implementation Guidelines](#immerse-issuer-implementation-guidelines)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Key Registry Service](#key-registry-service)
- [IMMERSE Issuer Endpoints](#immerse-issuer-endpoints)
- [Relation to Other Specifications](#relation-to-other-specifications)
- [Containerization - Docker Images](#containerization---docker-images)
- [Deployment with Kubernetes](#deployment-with-kubernetes)
- [Summary](#summary)
- [References](#references)

## Overview

The IMMERSE Credential Issuer implements the OpenID for Verifiable Credential Issuance (OID4VCI) protocol and the Selective Disclosure JWT (SD-JWT) Verifiable Credential (VC) standard (draft-ietf-oauth-sd-jwt-vc-12, 2025). The supporting Key Registry microservice provides a centralized directory for public key discovery that allows us to fetch up-to-date signing keys from issuers participating in the same cluster. The issuer and registry are containerized using Docker and deployed as Kubernetes workloads for reproducibility and scalability. Specifically, each pod runs a containerized Node.js service and exposes readiness and liveness probes.

## Key Registry Service

The key registry service serves as a supporting microservice that provides a temporary public-key directory for all issuers participating in the IMMERSE demo network. It provides an HTTP API for key discovery and rotation coordination across multiple issuers. It is not the issuer's JWKS endpoint defined by OID4VCI, but an internal directory that allows verifiers to discover valid signing keys quickly in a shared environment.

Each issuer registers its current public signing key through the `/register` endpoint.
The registry stores entries as:

```javascript
Map<kid, { publicKey, issuer, registeredAt }>
```

and exposes a JWKS view through GET /.well-known/jwks.json.

The JWKS response is filtered to include keys registered within a specified timeframe (in the context of this implementation, we have set this to be forty-eight hours). The registry utilizes RFC 7517 (JSON Web Key), RFC 7518 (JSON Web Algorithms), and RFC 7638 (JWK Thumbprint). Each key is exposed with use: "sig" and alg: "ES256". Note that the service does not sign its responses or authenticate submissions; it is a trusted component intended for controlled development and test environments.

The service assumes submitted JWKs are public-only. If a component accidentally includes private members (e.g., 'd') during the registration of a key, the service does not strip or reject them. It is the responsibility of the entity registering to ensure only public JWKs are sent. This SHOULD be changed for production. Additionally, any caller can register keys, as in this context, this is a trusted/demo component, not a hardened key directory/key management microservice.

The registry's endpoints are presented in the table as follows:

| Endpoint                     | Description                                                              |
| ---------------------------- | ------------------------------------------------------------------------ |
| `POST /register`             | Registers or updates an issuer public key (`kid`, `publicKey`, `issuer`) |
| `GET /.well-known/jwks.json` | Returns all keys registered within a specified timeframe                     |

## IMMERSE Issuer endpoints

*The diagram below demonstrates communication between the IMMERSE Issuer, the IMMERSE Wallet and the key registry service. Note: The Key Registry is an IMMERSE-specific component for key discovery and is not part of the standard OID4VCI protocol. Additionally, the registration arrow from Issuer to Key Registry represents a periodic process and does not necessarily occur during/after each issuance flow.*

```text
+-------------------+              +------------------+              +------------------+
|       Wallet      |              |      Issuer      |              |   Key Registry   |
+-------------------+              +------------------+              +------------------+
          |                                 |                                 |
          | GET /.well-known/openid-credential-issuer                         |
          |-------------------------------->|                                 |
          |<--------------------------------| Metadata (formats, endpoints)   |
          |                                 |                                 |
          | Open /authorize                 |                                 |
          |-------------------------------->|                                 |
          |<--------------------------------| Redirect to /callback           |
          |                                 | + Credential Offer (pre-authz)  |
          |                                 |                                 |
          | POST /token (pre-authz code, PoP JWT)                             |
          |-------------------------------->|                                 |
          |<--------------------------------| access_token + c_nonce          |
          |                                 |                                 |
          | POST /credential (PoP JWT with c_nonce)                           |
          |-------------------------------->|                                 |
          |<--------------------------------| SD-JWT-VC (dc+sd-jwt) +         |
          |                                 | disclosures (~ separated)       |
          |                                 |                                 |
          |                                 | Register new public key         |
          |                                 |-------------------------------->|
          |                                 |                                 |
          |<------------------------------------------------------------------|
          | Present credential + selective disclosures (to Verifier)          |
          +-------------------------------------------------------------------+
```

The IMMERSE Issuer implements the OpenID for Verifiable Credential Issuance (OID4VCI 1.0) specification, the SD-JWT-based Verifiable Credentials draft (draft-ietf-oauth-sd-jwt-vc-12), and the OAuth 2.0 Attestation-Based Client Authentication draft (version 7). Together, these protocols define a secure and privacy-preserving method for wallets to obtain digitally signed credentials that can later be verified by third parties, such as the IMMERSE Verifier. The issuer also follows the W3C Verifiable Credentials Data Model 2.0, particularly for the internal representation of credentials and loosely for the structure of revocation status information.

The IMMERSE Issuer exposes a set of endpoints that conform to the OID4VCI specification and are presented in the following table:

| Endpoint               | Specification Section                                  | Notes                                                                              |
| ----------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| Issuer Metadata     | OID4VCI sec.12                           | GET `/.well-known/openid-credential-issuer`, returns compliant metadata                 |
|Authorization     | OID4VCI sec.5                 | GET `/authorize` (redirects to `/callback`), deeplink for IMMERSE Wallet|
| Token Endpoint      | OID4VCI sec.6                                      | POST `/token`, supports pre-authorized code grant and OAuth 2.0 Attestation-Based Client Authentication [draft-ietf-oauth-attestation-based-client-auth-07], returns an access token                     |
| Credential Endpoint | OID4VCI sec.8                                      | Issues `dc+sd-jwt`, i.e. SD JWT VCs, see [draft-ietf-oauth-sd-jwt-vc-12]                               |
| JWKs of an IMMERSE Issuer          | OID4VCI             | GET `/.well-known/jwks.json`, Issuer’s public JWKs   |
| Revocation          | VC Data Model 2.0 and OID4VCI sec.13               | Exposes JSON status list with VC jtis that have been revoked at `/.well-known/credential-status.json`   |
| Liveness/ Readiness          | -               | GET /`healthz`, GET `/readyz`, Liveness/readiness probes for Kubernetes.   |

Upon startup, the issuer generates a fresh elliptic-curve key pair using the NIST P-256 curve (secp256r1), whose parameters are defined in NIST FIPS 186-5 (Digital Signature Standard). The public component is converted to JWK format and registered with the Key Registry for discovery by external verifiers (e.g. in the event of key rotation). Keys rotate automatically within a specified timeframe (in the context of this implementation, that is set to be every twenty-four hours). This aligns with the registry's forty-eight-hour (implementation specific) retention window and ensures that each credential signed with a current, ephemeral key can later be verified by an IMMERSE Verifier, even if the signing key has rotated. Keys are rotated on a scheduled basis to limit the exposure window in the event of key compromise, in accordance with the re-keying principles described in NIST SP 800-57, Part 1 Revision 5, Section 5.3.4, which states: "The cryptoperiod for the private key should be determined based on the sensitivity of the data, the volume of data protected, and the risk of key compromise." Note that the choice to set relatively short cryptoperiods is an intentional, implementation-specific choice for demonstration purposes. In a production environment, this value would typically be extended to reflect operational realities, risk tolerance, and performance considerations. Additionally, note that the issuer publishes its own JWKS endpoint at `/.well-known/jwks.json`, containing the active signing key under the current kid.

The issuer's configuration is exposed through a metadata document served from `/.well-known/openid-credential-issuer`. In accordance with Section 12 of the OID4VCI specification, this endpoint returns a JSON object that describes the supported credential formats, token, and credential endpoints. An example of the unsigned JSON response of the IMMERSE Issuer's endpoint to this endpoint follows:

```json
{
  "credential_issuer": "https://immerse-issuer.example.org",
  "token_endpoint": "https://immerse-issuer.example.org/token",
  "credential_endpoint": "https://immerse-issuer.example.org/credential",
  "credential_configurations_supported": [
    {
      "format": "dc+sd-jwt",
      "vct": "UniversityDegreeCredential",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      }
    },
    {
      "format": "vc+sd-jwt",
      "vct": "UniversityDegreeCredential",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      }
    }
  ]
}
```

The implementation supports the `dc+sd-jwt` format as specified in draft-ietf-oauth-sd-jwt-vc-12, which replaced the earlier `vc+sd-jwt` media type to avoid a naming conflict with the W3C's registered type. For backward compatibility, the issuer continues to accept both forms. <!--The issuer accepts both dc+sd-jwt and the deprecated vc+sd-jwt format for compatibility with older clients. However, all issued credentials conform to the dc+sd-jwt format as defined in draft-ietf-oauth-sd-jwt-vc-12.--> The metadata also lists the supported proof type (`jwt`), binding method (`jwk`), and signing algorithm (`ES256`). The issuer responds with an unsigned JSON document, which satisfies the mandatory form of the specification; it does not implement the optional signed metadata variant using JWS.

The credential issuance process follows the standard OID4VCI flow. A session begins at the `/authorize` endpoint, which establishes session state and redirects the user to `/callback`. At that stage, the issuer generates a pre-authorized code and constructs a credential offer in the form of an OpenID Credential Offer URI. This URI encodes all necessary information for the wallet to initiate the issuance process, including the credential type and grant type. The issuer's web interface embeds this link as a deep link that opens the wallet application directly, avoiding the need for manual code entry or QR scanning. Note that the option to copy the link is provided and the deeplink functionality is implemented in all three modes, namely; 2D, 3D and AR.

When the wallet calls the `/token` endpoint, it presents the pre-authorized code along with a Proof-of-Possession (PoP) JWT and a client attestation token. This endpoint enforces the Issuer side checks as defined in the attestation-based client authentication model described in the OAuth 2.0 Attestation-Based Client Authentication draft draft. Specifically, the issuer verifies the signature of the PoP JWT using the public key included in its header, validates the audience claim, checks the freshness of the issued-at timestamp, enforces a five-minute validity window, and rejects any replayed tokens using an in-memory jti cache. If a client attestation token is present, the issuer also verifies that its cnf.jwk field matches the PoP's key material. Upon successful validation, the issuer issues a short-lived bearer access token together with a c_nonce value, which the wallet must use to generate a proof during the credential request.

The `/credential` endpoint completes the issuance process. The wallet submits the access token and a signed PoP JWT that includes the c_nonce provided by the issuer. The issuer verifies the signature, checks the proof type (`typ = openid4vci-proof+jwt`), confirms that the audience matches the issuer's identifier, and ensures the nonce matches the expected value. Once validated, the issuer generates a university degree credential (implementation specific in the context of the Use Case) in the SD-JWT VC format. Each credential is represented as a signed JWT, whose payload follows the W3C Verifiable Credentials Data Model 2.0 structure, including @context, type, and credentialSubject fields. Selective disclosure is implemented by hashing individual claims with per-claim salts and encoding each as a disclosure element, as defined in the SD-JWT VC draft. The resulting credential is signed with the issuer's ES256 private key, given a one-year validity period, and returned alongside the disclosures concatenated with the tilde (`~`) separator. This construction matches the definition of an SD-JWT VC, allowing holders to selectively reveal claims without exposing others. The final SD-JWT VC is serialized according to [draft-ietf-oauth-sd-jwt-vc-12], where the base SD-JWT (the signed VC) is followed by one or more base64url-encoded Disclosures, each separated by a tilde (`~`):

```text
SD-JWT~Disclosure1~Disclosure2~...
```

The issuer supports credential revocation through a simple status list exposed at `/.well-known/credential-status.json`. This JSON document lists revoked credential identifiers (`jti` values) and is updated dynamically whenever an administrator calls the `/admin/revoke endpoint`. The representation follows the "StatusList2025" structure derived from the W3C Verifiable Credentials Data Model 2.0, enabling verifiers to confirm whether a credential remains valid. While simplified, the mechanism satisfies the model's core revocation semantics.

## Relation to other specifications

Proof-of-Possession follows Appendix F of OID4VCI and includes checks for header types such as `openid4vci-proof+jwt`, nonce validation, audiende check, etc. Client Attestation follows OAuth Attestation-Based Client Auth (-07 draft) and includes header parsing and cnf field check. The SD-JWT VC Format follows draft-ietf-oauth-sd-jwt-vc-12 and uses `application/dc+sd-jwt`; includes `_sd`, `_sd_alg`. Finally, the W3C VC Data Model v2.0 is used for `@context`, `type`, and `credentialSubject` structure.

## Containerization - Docker Images

Both the issuer and registry are containerized for portability and managed deployment. Each component includes its own Dockerfile: Dockerfile.issuer for the issuer and Dockerfile.registry for the registry. Both images use an official Node.js base image, i.e. `node:18-alpine` (small image size), install only the required dependencies, copy the relevant source files, and expose their respective ports (8000 for the issuer, 8080 for the registry). The containers run non-root processes and are designed to be orchestrated within a Kubernetes cluster.

| File                  | Purpose                                       | Notes                                                                                 |
| --------------------- | --------------------------------------------- | ------------------------------------------------------------------------------------- |
| `Dockerfile.issuer`   | Builds the Node.js OID4VCI issuer             | Exposes port 8000 |
| `Dockerfile.registry` | Builds the key registry microservice          | Exposes port 8080 |

## Deployment with Kubernetes

In Kubernetes, the deployment manifests define each component as a Deployment resource with one replica. The issuer deployment (`deployment-issuer.yaml`) specifies readiness and liveness probes targeting `/readyz` and `/healthz`, ensuring that Kubernetes only routes traffic to healthy pods and restarts containers that fail. The registry deployment (`deployment-registry.yaml`) is lighter and does not require probes because of its simple, stateless design. Each deployment is paired with a Service definition that exposes it on a stable internal cluster address (`service-issuer.yaml` and `service-registry.yaml`). The issuer service may also be exposed externally through an ingress, depending on the cluster configuration.

A small Kubernetes Secret named `issuer-secret.yaml` provides environment variables, such as ISSUER_BASE_URL and KEY_REGISTRY_URL. While it does not contain any cryptographic material, defining it as a Secret avoids warnings that would appear if the same data were stored in an unsealed ConfigMap. The issuer generates its signing keys dynamically at runtime and never stores private keys in the cluster's filesystem or configuration.

The system includes timing logs that measure each phase of the issuance process, namely; token request, proof verification, credential signing, and overall issuance. These logs are visible through Kubernetes using `kubectl logs` and can be filtered by trace identifiers to reconstruct end-to-end latency across the wallet, issuer, and verifier. The data serve both performance analysis and transparency goals, offering insight into how long each stage of the issuance takes in a live confidential environment.
Specifically, for the IMMERSE Issuer logs:

```bash
kubectl logs deploy/vc-issuer | grep '^\[timing\]'
```

## Security Considerations

This implementation includes security measures such as:

- PoP with nonce and replay protection
- Short-lived access tokens and signing keys
- Regular key rotation
- Client attestation verification

*Note: Comprehensive security considerations, threat analysis, and production hardening guidelines are documented separately in the Security Guidelines for IMMERSE Components doc.*

## Summary

This document outlines the implementation details and file structure of the IMMERSE Issuer and Key Registry services, along with their alignment to relevant specifications and drafts. The IMMERSE Issuer exposes a set of endpoints compliant with the OID4VCI specification, including metadata, token, and credential issuance endpoints. The Key Registry supports key rotation and discovery mechanisms. Together, these components demonstrate a complete pre-authorized code flow: a wallet instance requests and receives Verifiable Credentials (VCs), while verifiers can later validate their authenticity using published keys and associated revocation data.

## References

- OpenID Foundation, **OpenID for Verifiable Credential Issuance (OID4VCI) 1.0**, Final Specification, 2025. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- IETF OAuth WG, **Selective Disclosure JWT VC**, draft-ietf-oauth-sd-jwt-vc-12, 2025. [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- IETF OAuth WG, **OAuth 2.0 Attestation-Based Client Authentication**, draft-ietf-oauth-attestation-based-client-auth-07, 2025. [https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
- W3C, **Verifiable Credentials Data Model 2.0**, W3C Recommendation, 2024. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- NIST, **FIPS 186-5: Digital Signature Standard (DSS)**, 2023. [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- NIST, **SP 800-57 Part 1 Rev.5: Recommendation for Key Management - General**, 2020. [https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- IETF, **RFC 7517: JSON Web Key (JWK)**, 2015. [https://www.rfc-editor.org/rfc/rfc7517](https://www.rfc-editor.org/rfc/rfc7517)
- IETF, **RFC 7518: JSON Web Algorithms (JWA)**, 2015. [https://www.rfc-editor.org/rfc/rfc7518](https://www.rfc-editor.org/rfc/rfc7518)
- IETF, **RFC 7519: JSON Web Token (JWT)**, 2015. [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)
- IETF, **RFC 7638: JSON Web Key (JWK) Thumbprint**, 2015. [https://www.rfc-editor.org/rfc/rfc7638](https://www.rfc-editor.org/rfc/rfc7638)
- IETF, **RFC 8725: JSON Web Token Best Current Practices**, 2020. [https://www.rfc-editor.org/rfc/rfc8725](https://www.rfc-editor.org/rfc/rfc8725)
- IETF, **RFC 6749: The OAuth 2.0 Authorization Framework**, 2012. [https://www.rfc-editor.org/rfc/rfc6749](https://www.rfc-editor.org/rfc/rfc6749)

