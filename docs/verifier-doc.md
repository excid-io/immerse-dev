# IMMERSE Verifier: Implementation Guidelines

## Table of Contents

- [IMMERSE Verifier: Implementation Guidelines](#immerse-verifier-implementation-guidelines)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [OID4VP Presentation Flow](#oid4vp-presentation-flow)
- [Containerization - Docker image](#containerization---docker-image)
- [Deployment with Kubernetes](#deployment-with-kubernetes)
- [Security Considerations](#security-considerations)
- [Summary](#summary)
- [References](#references)

## Overview

The IMMERSE Verifier implements the OpenID for Verifiable Presentations (OID4VP) protocol and the Selective Disclosure JSON Web Token Verifiable Credential (SD-JWT VC) standard [draft-ietf-oauth-sd-jwt-vc-12]. It serves as the relying party that requests, receives, and verifies Verifiable Presentations (VPs) from a user's wallet (in the context of this repository the IMMERSE Wallet). Acting as the main verification component in the IMMERSE identity architecture, it consumes credentials issued by the IMMERSE Issuer, validates the cryptographic proofs of possession embedded within them, and determines their authenticity and integrity before granting access to protected experiences, such as the immersive classroom environment in the context of the use case presented in this repository.

From a design perspective, the verifier follows the same modular, containerized approach as the issuer. It is a lightweight Node.js service that exposes only a few HTTP endpoints. These endpoints enable the IMMERSE wallet to fetch presentation requests, post VPs, and retrieve optional configuration metadata. The service also provides readiness and liveness probes that allow Kubernetes to orchestrate it reliably.

The IMMERSE Verifier receives an SD-JWT combined serialization (a JWT followed by one or more base64url-encoded disclosures separated by the tilde (~) character) and verifies it in accordance with the rules defined in draft-ietf-oauth-sd-jwt-vc-12. The verifier re-computes the salted digests of each disclosed claim, checks them against the _sd array in the credential payload, confirms that all signatures are valid using the issuer's JWKs, and ensures that the credential is neither expired nor revoked. The verifier also enforces holder binding by comparing the key material used to sign the VP token with the cnf.jwk contained in the credential payload. This step ensures that the credential presented actually belongs to the holder who controls the corresponding private key. In doing so, the verifier implements the freshness and replay protection recommendations of OID4VP Section 14.1, using both a per-session nonce and a state parameter.

## OID4VP Presentation Flow

The IMMERSE Verifier implements the standard OID4VP request by reference flow. When a user interacts with the system, the verifier first creates a Request Object containing the parameters that define what kind of presentation it expects from the wallet. The request includes a unique session identifier, a cryptographically random nonce, a random state, a response_type set to `vp_token`, a `response_mode` of `direct_post`, and a `response_uri` indicating where the wallet must send its response. It also contains a `presentation_definition` that specifies which credential types and formats are acceptable, and which claims the verifier must to receive.

This request is stored at a unique URL of the form `/request/:sessionId` and the wallet is given a link using the `openid://` scheme, for example:

```bash
openid://?request_uri=https://verifier.example.org/request/abc123
```

The IMMERSE wallet dereferences the request_uri to obtain the JSON Request Object. Once it has satisfied the requirements described in the `presentation_definition`, it constructs a VP and posts it back to the verifier's `/presentation-callback` endpoint using the `direct_post` response mode defined in OID4VP Section 8. The POST body contains the VP token (SD-JWT-based structure) and, optionally, a `presentation_submission` object that describes which credentials were selected to fulfil each input descriptor in the original definition.

Upon receiving this response, the verifier performs a series of checks. It verifies that the nonce and state values match those that were issued in the request, ensuring that the presentation corresponds to the current session and cannot be replayed. It validates the digital signature of the VP token according to the corresponding standards (RFC 7517, RFC 7518, RFC 7519), confirms that the algorithm used is ES256, and reconstructs the disclosed claims to verify the integrity of the SD-JWT. The verifier then checks the credential's expiration and compares its unique jti against the issuer's revocation list served at `/.well-known/credential-status.json` (see issuer-doc.md and revoc-exp.md).

Only if all of these checks succeed does the verifier consider the presentation valid. The result is stored in a short-lived in-memory session representing a successful verification event. In the IMMERSE demo this triggers the granting of access to the immersive classroom session, effectively completing an end-to-end issuance and verification process between the issuer, the wallet, and the verifier.

The flow of messages between these components can be represented as follows:

```bash
+-------------------+              +------------------+              +------------------+
|       Wallet      |              |     Verifier     |              |      Issuer      |
+-------------------+              +------------------+              +------------------+
          |                                 |                                 |
          | GET /request/:id (Request URI)  |                                 |
          |-------------------------------->|                                 |
          |<--------------------------------| Request Object (nonce, state,   |
          |                                 | presentation_definition)        |
          |                                 |                                 |
          | POST /presentation-callback     |                                 |
          | (vp_token + presentation_submission)                              |
          |-------------------------------->|                                 |
          |                                 | Verify SD-JWT-VC, check nonce,  |
          |                                 | holder binding & revocation,    |
          |                                 | issuer signature & keys         |
          |                                 |                                 |
          |                                 | GET /.well-known/credential-    |
          |                                 | status.json                     |
          |                                 |-------------------------------->|
          |                                 | Check revocation status (jti)   |
          |                                 |                                 |
          |<--------------------------------| Verification result (success/   |
          |                                 | failure) & session_token        |
          |                                 |                                 |
          +-------------------------------------------------------------------+
          |                   Access to immersive classroom                   |
          +-------------------------------------------------------------------+
```

The IMMERSE Verifier exposes the following set of endpoints presented in the table:

| Endpoint                                | Specification Section                   | Notes                                                                      |
| --------------------------------------- | --------------------------------------- | -------------------------------------------------------------------------------- |
| `GET /request/:sessionId`               | OID4VP sec.5.10 (Request by reference)     | Returns the JSON Request Object the wallet fetches via its `request_uri`         |
| `POST /presentation-callback`           | OID4VP sec.8.2  | Wallet posts `vp_token`             |
| `GET /.well-known/openid-configuration` | OID4VP sec.12 (optional discovery)         | Advertises supported formats, etc |
| `GET /healthz`, `GET /readyz`           | —                                       | Kubernetes probes for container orchestration readiness                          |

## Containerization - Docker image

Similarly to the IMMERSE Issuer, the IMMERSE Verifier is distributed as a Docker image built from a minimal Node.js base image. Its Dockerfile copies only the necessary artifacts, installs the necessary dependencies, and runs the service under a non-root user with NODE_ENV=production. The image exposes port 5000 and no secrets or private keys are embedded within the image; any future keys would be provided through mechanisms such as Kubernetes Secrets.

## Deployment with Kubernetes

Deployment is handled by the Kubernetes manifests in `deployment-verifier.yaml` and `service-verifier.yaml`. Each Pod runs a single verifier container and publishes health and readiness endpoints (/healthz and /readyz) to allow Kubernetes to manage rolling updates and detect failures. The Service exposes the verifier inside the cluster on port 80, forwards traffic to the container's port 5000, and because it is a NodePort Service it is also reachable on node port 32000 on each cluster node.

A placeholder Secret manifest, `verifier-secret.yaml`, is included for consistency with the issuer's deployment structure. The current implementation does not store any sensitive information there, but the resource can be used later for TLS client certificates or encryption keys if encrypted direct_post.jwt responses are introduced.

The system includes timing logs that measure each phase of the verification flow, e.g., request retrieval, VP/VC signature verification, disclosure and holder-binding checks, revocation/status lookups, and end-to-end verification time. These logs are available using Kubernetes with kubectl logs and can be filtered by trace identifiers to reconstruct latency across the wallet, verifier, and issuer. The data are intended for performance analysis and operational transparency in live environments.

To view verifier timing entries:

```bash
kubectl logs deploy/verifier | grep '^\[timing\]'
```

## Security Considerations

This implementation incorporates the core security controls recommended in OID4VP Section 13 and related OAuth and SD-JWT VC standards:

- Replay protection using per-session nonce and state values that are valid only for a short time window.
- Holder binding enforcement by matching the key in the VP header against the credential's cnf.jwk claim.
- Credential integrity verification through SD-JWT selective disclosure checks (rehashing and comparing _sd digests).
- Signature validation against trusted issuer JWKs retrieved.
- Revocation and expiry checks using the issuer's `/.well-known/credential-status.json` endpoint and the credential's exp claim.

*Note: Comprehensive threat modeling, cryptographic validation procedures, and deployment hardening steps are detailed in the "Security Guidelines for IMMERSE Components" document.*

## Summary

The IMMERSE Verifier follows OID4VP to verify VPs containing SD-JWT VCs that provide a privacy-preserving credential format. By validating selective disclosures, cryptographic holder binding, and issuer authenticity, it demonstrates a practical and interoperable implementation of identity and access management suitable for immersive environments. The component's containerized design and integration with Kubernetes ensure it is easy to setup and reproducible.

## References

- OpenID Foundation, **OpenID for Verifiable Presentations (OID4VP) 1.0**, Final Specification, 2025. [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- OpenID Foundation, **OpenID for Verifiable Credential Issuance (OID4VCI) 1.0**, Final Specification, 2025. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- IETF OAuth WG, **Selective Disclosure JWT VC**, draft-ietf-oauth-sd-jwt-vc-12, 2025. [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- IETF, **RFC 7519: JSON Web Token (JWT)**, 2015. [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)
- IETF, **RFC 7517: JSON Web Key (JWK)**, 2015. [https://www.rfc-editor.org/rfc/rfc7517](https://www.rfc-editor.org/rfc/rfc7517)
- IETF, **RFC 7518: JSON Web Algorithms (JWA)**, 2015. [https://www.rfc-editor.org/rfc/rfc7518](https://www.rfc-editor.org/rfc/rfc7518)
- IETF, **RFC 7638: JSON Web Key (JWK) Thumbprint**, 2015. [https://www.rfc-editor.org/rfc/rfc7638](https://www.rfc-editor.org/rfc/rfc7638)
- IETF, **RFC 8725: JSON Web Token Best Current Practices**, 2020. [https://www.rfc-editor.org/rfc/rfc8725](https://www.rfc-editor.org/rfc/rfc8725)
- IETF, **RFC 6749: The OAuth 2.0 Authorization Framework**, 2012. [https://www.rfc-editor.org/rfc/rfc6749](https://www.rfc-editor.org/rfc/rfc6749)
- W3C, **Verifiable Credentials Data Model 2.0**, W3C Recommendation, 2024. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- NIST, **FIPS 186-5: Digital Signature Standard (DSS)**, 2023. [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
- NIST, **SP 800-57 Part 1 Rev.5: Recommendation for Key Management - General**, 2020. [https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
