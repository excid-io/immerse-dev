# IMMERSE

This is the development repository of the IMMERSE project. IMMERSE is a research and development project funded by the the [Spirit consortium](https://spirit-project.eu/consortium/). It demonstrates how Confidential Computing (CC) and Verifiable Credentials (VCs) can be combined to deliver secure and seamless identity and access management in immersive extended reality (XR) environments.

The IMMERSE ecosystem consists of three main entities: the Issuer, which issues VCs to holders, the verifier, which verifies Verifiable Presentations (VPs), and the wallet, which securely stores VCs and creates VPs to present to Verifiers on behalf of the user. In IMMERSE, the wallet runs inside a Confidential Virtual Machine (CVM), ensuring that credentials and keys remain protected even from the host infrastructure. By following open standards from W3C, OpenID, and the IETF, the project guarantees security, privacy and interoperability across ecosystems while keeping the user experience intuitive and uninterrupted.

Kubernetes provides the operational foundation for IMMERSE by managing wallets, issuers, and verifiers as containerized services. It ensures reproducible deployments, isolates workloads, and automates lifecycle tasks such as scaling and recovery.

Demos from the AR, 3D, and 2D UI experiences are available below. For higher-resolution versions with fewer edits, check out the [videos folder](videos/) .

## AR Demo with Headset

For the AR demo we used the [Galaxy S24 FE](https://www.samsung.com/us/smartphones/galaxy-s24-fe/?msockid=21a7056ac59a625d31e2131fc4486354) paired with the [XREAL AIR 2 PRO](https://next.xreal.com/air2/). Part 1 demonstrates the IMMERSE Wallet's AR scene and Credential Issuance, while part 2 shows the Verification process.

*Part 1: Credential Issuance*

https://github.com/user-attachments/assets/1c6bc739-af27-4ee1-9bff-fe98d5ce3002



*Part 2: Verification*


https://github.com/user-attachments/assets/fe09fd05-b0a9-4f86-a312-c34f869ccfd6



## 3D Experience Demo

https://github.com/user-attachments/assets/76683d20-1393-4130-9059-9d37c4d480a0



## 2D Experience Demo


https://github.com/user-attachments/assets/0a81d6f4-ede1-4df5-9d07-9aa98676ea66


## Available Documentation

We provide detailed documentation for every part of the IMMERSE ecosystem, from architecture and deployment to performance and security.

* [UseCase.md](docs/UseCase.md): Describes the IMMERSE use case.
* [UI-doc.md](docs/UI-doc.md): Presents the each entity’s user interface, including 2D, 3D, and AR modes built with WebXR.
* [wallet-doc.md](docs/wallet-doc.md): Presents the IMMERSE Wallet implementation, protocols (OID4VCI, OID4VP, SD-JWT, ABCA), and Kubernetes setup.
* [verifier-doc.md](docs/verifier-doc.md): Explains the Verifier’s OpenID4VP flow, and setup.
* [issuer-doc.md](docs/issuer-doc.md): Presents the Issuer’s implementation logic and setup.
* [Token-req.md](docs/Token-req.md): Explains the attestation-based /token request with all required headers and proofs.
* [revoc-exp.md](docs/revoc-exp.md): Explains how revoked and expired credentials are handled in the IMMERSE Ecosystem.
* [security.md](docs/security.md): Presents the security features and threat model of IMMERSE.
* [performance.md](docs/performance.md): Performance evaluation results.
* [wallet-guide.md](immerse-wallet/wallet-guide.md): Step-by-step guide for deploying the wallet and attestation service on Kubernetes.



