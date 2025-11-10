# Attestation-Based Client Authentication for the IMMERSE Ecosystem

This document outlines how the IMMERSE Wallet, operating inside a Confidential Virtual Machine (CVM), implements attestation-based client authentication, following the IETF specification for OAuth Attestation-Based Client Authentication.

**Aim**: Ensure that only trusted, authentic clients operating within verified environments can obtain Verifiable Credentials (VCs).

## 1. Introduction

This document defines the design and implementation of attestation-based client authentication for the IMMERSE Wallet operating within a Confidential Virtual Machine (CVM). The primary objective is to ensure that only wallet instances executing in trusted environments can obtain Verifiable Credentials (VCs) from IMMERSE Issuers, while maintaining full compliance with open standards including OAuth 2.0 Attestation-Based Client Authentication[^1], OpenID for Verifiable Credential Issuance (OID4VCI 1.0)[^2], Selective Disclosure JWT Verifiable Credentials (SD-JWT VC)[^3], and OpenID for Verifiable Presentations (OID4VP)[^4].

Traditional OAuth 2.0 authentication mechanisms, which rely on shared secrets or static public keys, lack the capability to verify that clients operate within genuine or uncompromised environments. The attestation-based approach extends this model by incorporating cryptographic proof of the wallet instance's execution environment. In the IMMERSE implementation, this is achieved through a certificate hierarchy where the CVM platform serves as the root of trust, establishing a verifiable chain from the Trusted Execution Environment (TEE) to each user's holder key.

## 2. Actors and Responsibilites

The IMMERSE ecosystem comprises four primary actors, each with distinct responsibilities in the attestation-based authentication model.

The **IMMERSE Wallet** runs in Kubernetes pods within a CVM and serves as the OAuth client and credential management software, responsible for generating and securely storing its own Client Instance Key (CI-Key) and managing Holder Keys for its users. It performs attestation-based authentication at the token endpoint using the CVM's Attester Key (A-Key), manages credential storage and presentation, and maintains its portion of the internal certificate hierarchy. The wallet acts as the user agent that performs cryptographic operations using the Holder's keys, granted that the Holder consented to the aforementioned operations.

The **IMMERSE Issuer** functions as both Authorization Server and Credential Issuer, validating attestation and Proof-of-Possession (PoP) JWTs according to the OAuth draft specification[^1]. <!--This entity issues SD-JWT VCs bound to Holder Keys and maintains the trust store of known Attester root certificates that support the verification process.-->

The **IMMERSE Verifier** validates the Holder's claims, requesting Verifiable Presentations (VPs) and verifying issuer signatures, holder bindings, and SD-JWT disclosures. Note that this component operates transparently with respect to the attestation mechanism, requiring no changes to support the enhanced authentication model.

The **Holder** represents the end user, who MAY be the subject of the VCs [^5] and is the owner of the Holder Key. For simplitcity, we assume the Holder and the subject are the same in the context of this document. The Holder authorizes both issuance and presentation of credentials through user consent interactions with the wallet software. The Holder Key is cryptographically bound to the Holder's identity in issued credentials, and the wallet performs signing operations on the Holder's behalf when creating presentations.

## 3. System Architecture

The IMMERSE Wallet architecture employs a hierarchical trust model where the CVM platform serves as the root attestation authority, individual Kubernetes pods operate as independent wallet instances, and each pod manages multiple user Holder Keys. This design maintains clear separation between platform identity, instance identity, and user identity.

This internal Public Key Infrastructure exists purely as a provenance mechanism, never appearing in OID4VCI[^2] or OID4VP[^4] payloads, so as to ensure privacy, unlinkability and interoperability. This design decision ensures privacy preservation, because exposing the full certificate chain in credential payloads would create significant correlation risks. If verifiers could see the complete chain from the Holder Key back to the CVM's root A-Key, they could potentially link all credentials issued to pods running on the same CVM across different contexts and services. This would undermine the selective disclosure capabilities that are fundamental to SD-JWT VC[^3], as the certificate chain would become non-disclosable metadata that travels with every presentation regardless of user consent.

Furthermore, introducing custom certificate extensions in credential payloads would create interoperability issues with standard verifiers that expect only the basic `cnf.jwk` structure. The OAuth Attestation Draft's requirements[^1] are properly confined to the token endpoint authentication headers and do not extend to credential payloads. In this way, credentials remain valid and verifiable even if Holders migrate to different CVMs, different wallet providers or interact with verifiers from other ecosystems.

Additionally, we ensure separation of concerns, by distinguishing between platform authentication and user identity representation. The wallet attestation proves ***"this pod/wallet instance is running on a legitimate CVM platform"*** through the OAuth token endpoint headers, while the Holder Key represents ***"this is the user's identity"*** in credential operations. These distinct concerns don't require cryptographic merging in the credential payloads themselves.

The architecture enables every Holder Key to be cryptographically traced back to the specific pod and CVM that generated it, providing precise revocation and audit capabilities while maintaining full standards compliance. The Holder maintains complete control over their keys and credentials, with the wallet serving as a secure execution environment for cryptographic operations.

## 4. Authentication Flow at Token Endpoint

### 4.1 Wallet Procedure

Each wallet pod begins by generating or loading its unique CI-Key material. The pod then constructs a **Client Attestation JWT** containing the public JWK of its CI-Key within the `cnf.jwk` claim, following the requirements in section 5.1 of the OAuth attestation specification[^1].

The pod submits this unsigned JWT, along with its Kubernetes service account token, to the **CVM Attestation Service**. This service validates the pod's legitimacy by calling the Kubernetes TokenReview API, which cryptographically verifies the pod's namespace and service account membership. Only pods running in authorized namespaces with approved service accounts receive A-Key-signed attestations.

The CVM Attestation Service then *signs the Client Attestation JWT with the CVM's A-Key* (the client attester's key) and returns it to the pod, in accordance with section 5.1 of the specification[^1]. Optionally, the signed JWT MAY include the A-Key certificate or full certificate chain in the JOSE header via the `x5c` parameter to facilitate issuer trust verification.

Simultaneously, the wallet builds a **PoP JWT** signed with its **CI-Key private key**, featuring a short lifetime of approximately 60 seconds and containing standard claims including `iss`, `aud`, `iat`, `exp`, `jti`, and an optional `challenge` parameter, as specified in section 5.2 of the specification[^1].

The wallet transmits the token request with both JWTs as dedicated headers while maintaining the standard `application/x-www-form-urlencoded` body format.

### 4.2 Issuer Procedure

Upon receiving a token request, the issuer first validates the presence and syntax of both attestation headers as defined in section 6.1 of the OAuth draft[^1]. The issuer then verifies the Attestation JWT using the trusted A-Key root or `x5c` certificate chain, extracts the `cnf.jwk` claim, and verifies the PoP JWT signature under the referenced CI-Key according to section 6.3 of the specification[^1].

The issuer performs critical claim consistency checks, validating that the `aud` claim matches the token endpoint and confirming JWT lifetimes and `jti` uniqueness meet policy requirements. If the Attestation JWT contains a `sub` claim (representing client identifier), the issuer MUST verify it matches the PoP JWT `iss` claim. In OID4VCI pre-authorized code flows where no `client_id` parameter is present in the request body, the `sub` claim is OPTIONAL, but recommended for audit purposes. Upon successful validation, the issuer issues an access token for credential endpoint access; upon failure, it returns appropriate OAuth error codes including `invalid_client_attestation`, `use_fresh_attestation`, or `use_attestation_challenge`. This process authenticates the wallet software instance, preparing for the subsequent Holder authentication during credential issuance.

## 5. Internal Certificate Chain and Provenance Model

### 5.1 Chain of Trust

The CVM maintains a hierarchical trust chain where the A-Key certificate functions as a root CA representing the **CVM platform identity**. Each wallet pod within the CVM operates with its own Client Instance Key (CI-Key) certificate, signed by the CVM's A-Key and serving as an intermediate certificate representing the **pod's identity**. Individual pods then manage multiple Holder Keys (HKs) as end-entity certificates signed by the pod's CI-Key, representing **Holders' cryptographic identities** for VC issuance and presentation.

This architecture provides both security isolation and operational flexibility and can be represented as follows:

```text
CVM Platform (A-Key-Root)
├── Pod 1 (CI-Key-1) → [HK-UserA, HK-UserB...]
├── Pod 2 (CI-Key-2) → [HK-UserC, HK-UserD...]
└── Pod 3 (CI-Key-3) → [HK-UserE, HK-UserF...]
```

where userA, userB access their wallet through Pod 1, userC, userD access their wallet through Pod 2, userE, userF access their wallet through Pod 3, and so on.

**CVM-Level (A-Key)**: Represents the trusted execution environment platform identity. The A-Key is provisioned during CVM deployment and serves as the root of trust for the entire platform.

**Pod-Level (CI-Keys)**: Provides isolation between wallet instances running in the same CVM. Each pod has independent OAuth authentication sessions and key management.

**User-Level (HKs)**: Individual Holder Keys within each pod, providing cryptographic separation between users.

This cryptographic provenance model ensures that each Holder Key can be traced to its specific pod instance and CVM platform while maintaining operational separation between users.

### 5.2 Implementation Guidelines

The CVM's A-Key is provisioned during initial deployment through secure mechanisms such as SSH-based key injection at boot time. The CVM Attestation Service manages access to the A-Key private material for signing pod attestations.

Within each wallet pod, the wallet maintains certificate management logic for generating its CI-Key pair and obtaining a certificate signed by the CVM's A-Key via the attestation service. When generating new Holder Keys, the pod issues short-lived certificates signed by its CI-Key, storing these certificates locally for audit and provenance purposes without exposing them in protocol payloads. The Holder maintains ultimate control over when and how these keys are used through explicit consent mechanisms.

The issuer maintains a trust store of known CVM A-Key root fingerprints or certificates, validating attestation JWT `x5c` chains against these trusted roots during the authentication process. At the verifiable credential layer, the `cnf.jwk` claim references only the Holder Key.

When a CVM platform compromise is detected through the mechanisms described in Section 8, the A-Key is revoked in the platform's revocation registry. This automatically invalidates all CI-Key certificates signed by that A-Key, preventing compromised pods from authenticating to issuers.

## 6. Standards Compliance

The implementation maintains full compliance across all relevant specifications (cited at the end of the document). At the token endpoint layer, the system adheres to OAuth Attestation-Based Client Authentication through proper use of Attestation and PoP JWTs as defined in the draft specification. For credential issuance, OID4VCI 1.0 compliance is maintained without modification through continued use of form-encoded requests and proper Holder binding. The credential data model follows SD-JWT VC 1.0 specification with `cnf.jwk` correctly referencing the Holder Key, while presentation flows comply with OID4VP 1.0 through signatures generated with the Holder Key on behalf of the Holder.

This architectural approach delivers provenance and revocation capabilities without modifying standard message formats or claims, ensuring interoperability across the broader verifiable credentials ecosystem while preserving the fundamental relationship between Holder and credential.

## IMMERSE Component Modifications

### 7.1 IMMERSE Wallet Modifications

Each wallet pod requires implementation of certificate management logic capable of generating its own CI-Key pair and managing Holder Keys for its users. The pod MUST interface with the CVM Attestation Service to obtain A-Key-signed attestations for its CI-Key.

Existing JWT-building functions are extended to support:

- Construction of unsigned Attestation JWTs containing the pod's CI-Key public JWK in `cnf.jwk` claims.
- PoP JWT signing with the pod's CI-Key private key.
- Optional `x5c` header processing for certificate chain inclusion.

The pod MUST implement a local certificate registry mapping its Holder Key thumbprints to the pod's CI-Key, provide secure storage mechanisms for keys and certificates within the pod's memory, and expose interfaces for certificate status reporting. Additionally, the pod MUST maintain clear separation between its CI-Key and Holder Keys, ensuring that user consent is obtained for all Holder Key operations.

### 7.2 IMMERSE Issuer Modifications

The issuer's token endpoint requires modifications to verify Attestation and PoP JWTs including optional `x5c` certificate chain validation. The JWT verification module MUST be extended to parse Attestation JWTs and `x5c` headers, validate signature chains against the A-Key trust store, extract `cnf.jwk` claims, and verify PoP JWT signatures.

The issuer MUST implement error handling compliant with the OAuth draft specification[^1] and maintain an internal database mapping A-Key thumbprints to status indicators (active/revoked). Additionally, revocation endpoint or policy service components MAY require modification to periodically check wallet status lists for revoked A-Key roots. The credential issuance endpoint remains unchanged in its handling of Holder authentication and binding.

### 7.3 Unaffected Components

The IMMERSE Verifier requires no protocol changes, continuing to validate SD-JWT VC signatures, verify holder binding via `cnf.jwk` claims, and optionally query issuer revocation or status services when provenance checks are enabled. The Holder's experience and control remain fundamentally unchanged, as the wallet enhancements operate transparently to provide additional security without altering the user's role as credential subject and controller. Supporting infrastructure MAY include OPTIONAL key registry or CA services for A-Key and CI-Key tracking, CRL management, and auditing, plus policy services defining trust lifetimes, key rotation intervals, and revocation rules.

## 8. CVM Health and Revocation

The mechanisms for CVM compromise detection, health attestation, and infrastructure-level key revocation are considered out of scope for this specification, as they represent broader platform security concerns rather than protocol-level interactions.

Assumptions:

- CVM Health Monitoring: We assume the existence of platform-level services that monitor CVM integrity and can trigger revocation when compromise is detected.

- Time-Bound Attestations: This implementation assumes A-Key attestations are time-bound (recommended: 24-48 hours), providing natural expiration that limits the impact of potential compromise.

- Revocation Infrastructure: We assume the availability of revocation services (centralized registry, decentralized ledger, or platform-native mechanisms) that issuers can query for A-Key status.

This is due to the following factors:

- Separation of Concerns: CVM platform security is distinct from credential issuance protocols.

- Ecosystem Flexibility: Different deployments may use different attestation/revocation mechanisms.

- Standard Compliance: The core OID4VCI/OID4VP flows remain standards-compliant regardless of underlying CVM management.

- Implementation Agnostic: This specification works with any CVM health monitoring system.

The specification requires that:

- Issuers, i.e. in this context instances of the IMMERSE Issuer, validate A-Key attestations during token endpoint authentication

- Revocation status checking occurs, but the mechanism is implementation-defined.

- Credential issuance proceeds only for active, non-revoked wallet instances.

The specific implementation of CVM health monitoring and A-Key revocation is delegated to the platform layer.

## 9. Security and Operational Benefits

The architecture delivers multiple security and operational benefits through its layered design. Environment integrity is ensured through attestation of the **CVM platform** via A-Key root certificates, while **pod instance authenticity** is established through OAuth Attestation and PoP JWTs using per-pod CI-Keys.

User credential binding follows SD-JWT VC standards with Holder Keys in `cnf.jwk` claims, maintaining that the Holder is the credential subject. Provenance and auditability is achieved through the internal certificate chain from A-Key (CVM) to CI-Key (pod) to Holder Key (user), enabling tracing of credential origins back to specific platform and instance identities.

Privacy and compliance requirements are met by maintaining the certificate chain internally without exposing user-linking data in protocol transmissions, preserving the Holder's privacy, while providing enterprise-grade security controls. The pod-level isolation limits the impact of individual pod compromise while maintaining operational efficiency across the CVM platform.

## 10. Conclusion

The IMMERSE attestation-based client authentication architecture enables wallet instance verification while maintaining full standards compliance and preserving the Holder's complete control over their data and identity. Through its internal certificate hierarchy and provenance model, the system delivers cryptographic tracing of key origins, efficient revocation capabilities, and robust security controls without compromising interoperability with existing OID4VCI and OID4VP implementations. The combination of standards-compliant protocol implementation and operational security measures provides a solid foundation for trustworthy VC ecosystems in confidential computing environments, ensuring that Holders maintain control of their digital identities while benefiting from enterprise-grade security protections.

[^1]:[OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)

[^2]:[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

[^3]:[SD-JWT-based Verifiable Credentials (SD-JWT VC)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)

[^4]:[OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

[^5]:[Verifiable Credentials Data Model v2.0: 1.2 Ecosystem Overview](https://www.w3.org/TR/vc-data-model-2.0/#:~:text=more%20verifier%20policies.-,1.2%20Ecosystem%20Overview,-This%20section%20is)
