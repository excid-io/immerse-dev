# IMMERSE Wallet: Implementation Guidelines

## Table of Contents

* [IMMERSE Wallet: Implementation Guidelines](#immerse-wallet-implementation-guidelines)
* [Overview](#overview)
* [System Architecture](#system-architecture)
* [Kubernetes Integration and Security Isolation](#kubernetes-integration-and-security-isolation)
* [Containerization and Deployment Notes](#containerization-and-deployment-notes)
* [Security Considerations](#security-considerations)
* [Summary](#summary)
* [References](#references)

## Overview

The IMMERSE Wallet is the entity that acts on behalf of the Holder within the IMMERSE identity and access management ecosystem. It receives, stores, and presents Verifiable Credentials (VCs) using OpenID standards. Specifically, it relies on three complementary standards: OpenID for Verifiable Credential Issuance (OID4VCI), which defines how the wallet requests and receives credentials, OpenID for Verifiable Presentations (OID4VP), which defines how the wallet proves claims to verifiers, as well as the IETF Selective Disclosure JWT for Verifiable Credentials (SD-JWT VC) that lets the Holder reveal or hide individual claims, so the wallet transmits only the data that is strictly required, unless the holder wishes to reveal more. The IMMERSE Wallet integrates IETF's OAuth 2.0 Attestation-Based Client Authentication into the OID4VCI flow, specifically at the '/token' to ptove that the wallet instance is running in a genuine execution environment.

In the context of the IMMERSE project, the aforementioned execution environment is a Confidential Virtual Machine (CVM), specifically AMD SEV. Inside each CVM, an attestation service runs in a dedicated Kubernetes namespace (cvm-security) and holds the platform's root attestation key (we refer to this as A-Key, in the comments in the code and sometimes in the docs), each wallet pod is responsible for generating its own Client Instance Key (we refer to this as CI-Key, in the comments in the code and sometimes in the docs). The wallet pods run in a separate namespace (cvm-wallets) and they call the attestation service to obtain signed attestation JWTs and include them in the token requests, when authenticating to the IMMERSE Issuer. By isolating attestation logic from wallet operations, this design protects the attestation root (the A-Key), even if a wallet pod were compromised. This implementation demonstrates how Confidential Computing (CC) and attestation-based authentication can extend standard OpenID flows to deliver stronger, end-to-end assurance in digital identity systems, and, by extension, immersive XR environments.

## System Architecture

<!--From a high level perspective, the wallet comprises three cooperating components, namely, the frontend, the gateway, and the backend. All three components run in the CVM. The frontend is the component the user interacts with. It provides a responsive web interface that supports 2D, 3D, and a fully immersive AR mode through WebXR (see more in UI-doc). It never handles any private keys, tokens, or other secret material. Instead, it communicates only through a small set of API calls, all of which are passed to the gateway. The gateway is a lightweight Node.js service that sits between the browser and the wallet backend. Its main job is to make communication safe and simple. It serves the frontend files, manages HTTPS, and forwards specific API requests to the backend. The gateway hides internal backend endpoints from the public network and enforces consistent security headers (such as CORS, Content Security Policy, and Same-Origin controls). This makes the system easier to secure and prevents the frontend from directly exposing protocol traffic. In Kubernetes, the gateway also provides a clear separation of concerns - the frontend and backend can scale independently, while the gateway keeps their communication rules consistent. The backend implements the protocol logic. It handles OID4VCI and OID4VP flows, manages VC storage, and produces VPs on demand. The backend keeps the Holder's private key in memory inside the CVM, constructs proof-of-possession JWTs, and interacts with the Attestation Service (which is in a separate namespace) whenever it needs to prove that the wallet instance itself is running in a trusted environment. When a user accepts a credential offer, the frontend triggers an API call through the gateway to the backend, which then performs the OID4VCI flow with the issuer - requesting, signing, and storing the resulting SD-JWT VC. The credential is displayed through the frontend. Later, when the user needs to present that credential to a verifier, the backend builds an OID4VP presentation and signs it with the same Holder key, while the frontend shows a confirmation and redirects the user to the immersive classroom.-->

<!-- PREV COMMENT: The diagram below demonstrates the communication between all IMMERSE entities. Note that internal and external labels are in respect to the CVM. The frontend, backend and attestation service are in the CVM, while the issuer and verifier are outside in a different node. The user also does not need access to the CVM, here we use ngrok but https access can also be achieved with self-sogned certificates.-->
<!--The diagram below demonstrates the communication patterns between all IMMERSE ecosystem entities. The terms "internal" and "external" refer to components located inside or outside the CVM. The WebXR Device API specification mandates secure contexts (HTTPS) for accessing immersive AR capabilities. This browser security policy prevents malicious sites from accessing sensitive XR hardware without proper authentication. Our frontend therefore requires HTTPS to launch AR mode, authenticate with XR devices, and access spatial tracking features. While internal CVM components use HTTP for efficiency, all external-facing endpoints (frontend, issuer, verifier) employ HTTPS to meet WebXR security requirements and enable immersive classroom experiences. While we currently use ngrok tunneling for external accessibility in development, production deployments can utilize properly signed TLS certificates for HTTPS termination. The user never requires direct CVM access, interacting solely through the frontend interface.-->
The IMMERSE Wallet consists of three cooperating components that together realize the Holder role within the IMMERSE ecosystem: the frontend, the gateway, and the backend. All three run inside the CVM. The frontend is the user-facing component. It provides a responsive web interface that supports 2D, 3D, and fully immersive AR modes through WebXR (see UI-doc). The frontend never handles private keys, tokens, or any other secret material. Instead, it communicates with the rest of the system only through a small and well-defined set of API calls that are proxied by the gateway. The gateway is a lightweight Node.js service positioned between the browser and the wallet backend. Its primary role is to make communication both secure and simple. It serves static frontend files, manages HTTPS termination, and forwards selected API requests to the backend. By hiding internal backend endpoints from the public network, it enforces strict separation between external and internal traffic. The gateway also applies consistent security headers -such as CORS, Content-Security-Policy, and Same-Origin restrictions- protecting the wallet from browser-side injection or cross-origin exploitation. In Kubernetes, this component further simplifies scaling: the frontend and backend can scale independently, while the gateway preserves uniform security and routing policies.

The Backend contains the wallet's protocol logic and state. It handles OID4VCI and OID4VP flows, manages credential storage, communicates with the attestation service and creates VPs. Within the CVM, it generates and maintains the Holder's private key securely in memory, constructs proof-of-possession JWTs, and interacts with the Attestation Service, which runs in a separate namespace, to obtain client attestation JWTs whenever it must prove that the wallet instance is operating in a trusted environment to the issuer. When a user accepts a credential offer, the frontend forwards it through the gateway to the backend. The backend then executes the OID4VCI protocol with the issuer: it first requests a client attestation JWT from the Attestation Service, creates the PoP JWT and uses them to authenticate with the issuer through attestation-based client authentication headers (client-attestation and client-attestation-pop), and finally obtains and stores the resulting SD-JWT VC. The credential is then displayed to the user through the frontend. Later, when the user initiates communication with a verifier, the backend generates a VP signed with the holder's private key, while the frontend handles user confirmation, consent and warning messages, and, upon successful verification, redirects to the immersive classroom.

The diagram below shows communication patterns between all IMMERSE components. "Internal" refers to communication confined within the CVM, while "external" designates traffic leaving the CVM boundary. The WebXR Device API mandates secure contexts (HTTPS) to access immersive XR capabilities. This requirement protects against malicious web origins accessing XR hardware without explicit user consent. Consequently, the IMMERSE frontend uses HTTPS to establish a secure session with the browser and to authenticate with XR devices. Internal CVM communication between components (gateway - backend - attester) uses HTTP for efficiency, while all external interfaces (frontend - user, backend - issuer, backend - verifier) operate over HTTPS. During development, external exposure is achieved through Ngrok tunneling. In production deployments can utilize properly signed TLS certificates for HTTPS termination. The user never requires direct CVM access, interacting solely through the frontend interface.

```text
+-------------------+      HTTPS       +-------------------+
|       User        | <--------------> |     Frontend      |
|   (Browser/XR)    |                  |     (WebXR UI)    |
+-------------------+                  +-------------------+
                                              |
                                              | HTTP (internal)
                                              v
                                        +-----------------+
                                        |     Gateway     |
                                        |  (CORS/Proxy)   |
                                        +-----------------+
                                              |
                                              | HTTP (internal)
                                              v
+-------------------+      HTTP       +-------------------+
|  Attestation Svc  | <-------------> |      Backend      |
|   (cvm-security)  |                 |  (Wallet logic)   |
+-------------------+                 |    cvm-wallets    |
                                      +-------------------+
                                              |         \
                                              | HTTPS     \ HTTPS
                                              v           v
                                       +-------------+  +-------------+
                                       |    Issuer   |  |   Verifier  |
                                       |  (External) |  |  (External) |
                                       |   OID4VCI   |  |    OID4VP   |
                                       +-------------+  +-------------+
```

From a user perspective, the wallet lifecycle begins when the frontend receives an OpenID Credential Offer deep link. The frontend forwards the offer to the backend via the gateway, where the backend uses its CI-Key to obtain a client attestation JWT from the Attestation Service, and requests a token from the issuer with the attestation-based client authentication headers (client-attestation and client-attestation-pop) and JWTs. The backend creates an openid4vci-proof+jwt signed with the Holder key and makes a post request to the /credential endpoint and stores the returned SD-JWT VC (granted verification was successful). For verification, the backend resolves the request_uri and gets the nonce, state, and presentation definition. It creates a VP token signed with the Holder key. The backend then creates the vp_token, based on what the user wishes to disclose, and sends it to the verifier. Verification results are displayed in the frontend, and successful verification grants access to the immersive classroom.

In detail, the wallet follows the OID4VCI protocol using the pre-authorized code grant. It POSTs to the issuer's `/token` endpoint using `application/x-www-form-urlencoded` and includes both a client attestation JWT (signed by the CVM's A-Key by the Attestation Service) and a PoP JWT signed with the wallet's CI-Key (Client Instance Key). After receiving the `access_token` and `c_nonce` from the issuer, the wallet calls the `/credential` endpoint with a proof JWT signed by the Holder's private key. The wallet requests the `dc+sd-jwt` format, and the returned SD-JWT VC is stored as the canonical concatenation of the signed JWT followed by disclosures separated with tildes:

```text
SD-JWT~Disclosure1~Disclosure2~...
```

For OID4VP, the wallet resolves a request_uri and uses the verifier's fresh nonce and state with the direct_post response mode to submit the vp_token. The wallet can selectively disclose claims by including only the required disclosures from the SD-JWT VC, based on the verifier's presentation definition and user consent. Specifically, the wallet finds which of the Holder's VCs match the claims requested by the verifier and presents all the claims the Holder could potentially disclose from those VCs. Selective disclosure allows the user to decide which claims to reveal. The frontend displays all available credential claims, marking those explicitly requested by the verifier as recommended. The holder must still consent to their disclosure. If essential claims are withheld, access to the immersive classroom is denied. The protocol flows, as implemented by all IMMERSE entities, are depicted in the following sequence diagram:

```text
+-------------------+    +-------------------+    +-------------------+    +-------------------+    +-------------------+
|       User        |    |       Wallet      |    | Attestation Svc   |    |       Issuer      |    |     Verifier      |
|   (Browser/XR)    |    |   (CVM instance)  |    |   (CVM security)  |    |   (OID4VCI 1.0)   |    |                   |
+-------------------+    +-------------------+    +-------------------+    +-------------------+    +-------------------+
         |                        |                      |                        |                        | 
         | Credential Offer link  |                      |                        |                        |
         |----------------------->|                      |                        |                        | 
         |                        | sign client attest.  |                        |                        |
         |                        |     JWT request      |                        |                        |
         |                        |--------------------->|                        |                        | 
         |                        |<---------------------|                        |                        | 
         |                        |     Signed JWT       |                        |                        | 
         |                        |                   POST /token (JWT + PoP JWT) |                        | 
         |                        |---------------------------------------------->|                        | 
         |                        |<----------------------------------------------|                        | 
         |                        | access_token + c_nonce                        |                        | 
         |                        | POST /credential                              |                        | 
         |                        |---------------------------------------------->|                        | 
         |                        |<----------------------------------------------|                        | 
         |                        | SD-JWT VC (dc+sd-jwt)                         |                        | 
         |<-----------------------| Notify user, store credential                 |                        |
         |                        |                      |                        |                        | 
         | Navigate to verify     |                      |                        |                        |
         |----------------------->|                      |                        |                        |
         |   request_uri          | Resolve request_uri  |                        |                        |
         |                        |--------------------->|                        |                        | 
         |<----------------------------------------------| Consent UI: show       |                        |
         |                        |                      | recommended claims     |                        | 
         | User consents          |                      |                        |                        |
         |----------------------->| Build vp_token (Holder-signed, selective disclosure)                   |  
         |                        | send VP              |                        |                        |
         |                        |----------------------------------------------------------------------->|
         |                        | Verify VP            |                        |                        |         
         |                        |<-----------------------------------------------------------------------|         
         |<-----------------------| Verification result displayed, grant/deny access, session_token        |     
```

## Kubernetes Integration and Security Isolation

The deployment uses two namespaces to separate concerns: `cvm-wallets` holds the wallet frontend, gateway, and backend, while `cvm-security` hosts the attestation service. This  approach ensures that functional logic (issuance and presentation) is separated from trust roots and attestation signing keys. While namespaces themselves do not enforce strict isolation, IMMERSE strengthens them with Role-Based Access Control (RBAC) and NetworkPolicy to enforce boundaries at runtime. Each namespace uses its own ServiceAccount, which is the foundation for pod-level authentication. The attestation service runs under `cvm-attester-sa` in the `cvm-security` namespace. The Wallet backend runs as `wallet-sa` in the `cvm-wallets` namespace. When the backend requests a client attestation JWT, it includes its own Kubernetes ServiceAccount token, which the attestation service verifies using Kubernetes' native TokenReview API. This ensures that only authenticated pods in the allowed namespace-ServiceAccount pair (`cvm-wallets:wallet-sa`) can receive client attestation JWTs.

A NetworkPolicy named `allow-wallets-to-attester` in the `cvm-security` namespace strictly limits inbound traffic to the attestation service. Only pods in the `cvm-wallets` namespace with the expected label may connect to the attester's service port (5000).
Note that by default, wallet pods can reach external endpoints (such as issuer and verifier) and could reach other services unless additional egress restrictions are applied. Note also that the Attester is inaccessible to any other namespace: NetworkPolicy blocks all ingress except from `cvm-wallets`. Other namespaces may still resolve the service name, but any attempt to connect will be denied, even if the pod network is shared.

The attestation service protects its cryptographic keys inside the CVM by using SoftHSM, which provides a PKCS#11 token with persistent storage managed through Kubernetes. Initialization is handled by a one-time Job (softhsm-init-token.yaml) that creates a token labeled IMMERSE and generates the Attestation Key (A-Key). The PINs required to unlock the token are placed in a Kubernetes Secret and sealed with Bitnami Sealed Secrets. The plaintext Secret file is used only locally to generate the sealed version and should never leave the CVM or be committed to a repository. The Git repository contains only the sealed (encrypted) YAMLs, which are safe to store because they can only be decrypted by the Sealed Secrets controller inside the cluster.

Using SoftHSM in a Confidential VM might appear redundant at first glance, but in practice, it complements the protections offered by AMD SEV. SEV guarantees memory confidentiality against a malicious host, but it does not enforce how keys are used inside the guest. SoftHSM adds that internal boundary: keys are referenced only by handles, marked non-exportable, and restricted to specific operations such as signing (e.g. not decryption). This prevents accidental leakage of private key material. SEV protects the VM boundary from the host, while SoftHSM enforces non-exportability and controlled usage of keys inside the VM. It also gives the attestation service a PKCS#11 abstraction, which can later be updated to another mechanism without changing the wallet or attestation logic.

Networking in the IMMERSE CVM cluster is provided by Cilium, which enforces fine-grained, label-aware NetworkPolicies. This makes the `allow-wallets-to-attester` rule resilient to pod rescheduling or scaling, ensuring that traffic is consistently restricted to the intended namespaces and services. In practice, this forms the isolation boundary that prevents unintended communication between pods across namespaces.

## Containerization and Deployment Notes

All components provide logs and expose simple health endpoints for Kubernetes liveness/readiness probes. The frontend container serves static assets and the WebXR application, the gateway terminates browser calls, applies CORS and header policy, and forwards a minimal surface to the backend. The backend container hosts the issuance/presentation protocol flows, key handling, and attestation based client authentication integration. The Attester container runs in the `cvm-security` namespace, owns the SoftHSM token, and exposes a narrow API for creating/signing attestation artifacts. This simplifies operations: each unit has a single responsibility, image builds are reproducible, and runtime trust boundaries are explicit and testable with NetworkPolicy.

## Security Considerations

The wallet leverages `nonce` and `state` values for replay protection when making requests to both the verifier and the issuer, following OID4VCI and OID4VP mandates. It applies the appropriate headers for each request, ignores unknown parameters, and restricts CORS at the gateway so that only intended frontend origins can submit UI traffic. The backend generates the Holder key (P-256) inside the CVM and never persists the private component to disk in the demo. As specified by attestation-based client authentication, the attestation service issues a client-attestation JWT that includes the CI-Key's public JWK, and the wallet then proves possession of the CI-Key by producing a client-attestation-pop JWT signed with that key and scoped to the issuer's /token audience. This binds the attestation to the live request, ensuring that only a wallet instance with both a valid attestation and control of its CI-Key can obtain tokens. Additionally, only the wallet pods can obtain signed JWTs from the attestation service. This is implemented with kubernetes as follows:

* The attestation service verifies the caller's ServiceAccount token through the Kubernetes TokenReview API.
* Only pods running under the allowed namespace/service account pair (in the context of this implementation `cvm-wallets:wallet-sa`) are authorized.
* Once verified, the service signs the attestation JWT using the A-Key stored in SoftHSM via PKCS#11.
Furthermore, the A-Key is generated and stored inside SoftHSM, where it is marked non-exportable and accessed only through PKCS#11 operations. This ensures that even within a CVM, the private component of the A-Key never leaves the HSM boundary. Using SoftHSM provides defense in depth: the CVM guarantees hardware-backed isolation, while SoftHSM enforces cryptographic key lifecycle rules and non-exportability. In detail, SoftHSM adds an additional logical boundary, since even if CVM isolation is bypassed, the A-Key remains protected by the HSM abstraction. SoftHSM enforces proper key generation, labeling, and non-exportability, ensuring that the A-Key is managed consistently across deployments. Moreover, by confining signing operations to SoftHSM, every use of the A-Key can be logged and monitored, which ensures auditability.

Finally, with SD-JWT, selective disclosure is enforced: only the claims required by the verifier's presentation definition are marked as recommended. The frontend displays all available credential claims, highlighting those requested by the verifier, but the Holder must still provide explicit consent. In this way, the user retains complete control over which attributes are disclosed. Note that if essential claims are not disclosed, they will prevent access to the immersive classroom.

## Summary

The IMMERSE Wallet leverages OID4VCI, OID4VP, and the SD-JWT VC protocol, while integrating Attestation-Based Client Authentication to attest that the environment in which it runs is a genuine execution environment. The architecture consists of the user UI (frontend), the protocol and key operations (backend), a gateway, and an attestation service. The separation between those components is largely enforced through Kubernetes. Specifically, namespaces separate roles, RBAC limits privileges, NetworkPolicy restricts traffic, and SoftHSM enforces key usage inside the CVM. This implementation shows how confidential computing and attestation-based authentication can be integrated with standard OpenID flows to provide stronger end-to-end assurance for digital identity and immersive XR systems.

## References

* OpenID Foundation, **OpenID for Verifiable Credential Issuance (OID4VCI) 1.0**, Final Specification, 2025. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
* OpenID Foundation, **OpenID for Verifiable Presentations (OID4VP) 1.0**, Working Draft, 2025. [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
* IETF OAuth WG, **Selective Disclosure JWT VC**, draft-ietf-oauth-sd-jwt-vc-12, 2025. [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
* IETF OAuth WG, **OAuth 2.0 Attestation-Based Client Authentication**, draft-ietf-oauth-attestation-based-client-auth-07, 2025. [https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
* W3C, **Verifiable Credentials Data Model 2.0**, W3C Recommendation, 2024. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
* IETF, **RFC 7517: JSON Web Key (JWK)**, 2015. [https://www.rfc-editor.org/rfc/rfc7517](https://www.rfc-editor.org/rfc/rfc7517)
* IETF, **RFC 7518: JSON Web Algorithms (JWA)**, 2015. [https://www.rfc-editor.org/rfc/rfc7518](https://www.rfc-editor.org/rfc/rfc7518)
* IETF, **RFC 7519: JSON Web Token (JWT)**, 2015. [https://www.rfc-editor.org/rfc/rfc7519](https://www.rfc-editor.org/rfc/rfc7519)
* IETF, **RFC 7638: JSON Web Key (JWK) Thumbprint**, 2015. [https://www.rfc-editor.org/rfc/rfc7638](https://www.rfc-editor.org/rfc/rfc7638)
* IETF, **RFC 8725: JSON Web Token Best Current Practices**, 2020. [https://www.rfc-editor.org/rfc/rfc8725](https://www.rfc-editor.org/rfc/rfc8725)
