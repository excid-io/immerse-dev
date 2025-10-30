# IMMERSE Ecosystem Use Case: XR Learning

## Table of Contents

* [IMMERSE Ecosystem Use Case: XR Learning](#immerse-ecosystem-use-case-xr-learning)
* [Table of Contents](#table-of-contents)
* [Overview](#overview)
* [Actors and Roles](#actors-and-roles)
* [Use Case Scenario Description](#use-case-scenario-description)
* [Example Credential](#example-credential)
* [Verifier's Presentation Definition Example](#verifiers-presentation-definition-example)
* [References](#references)

## Overview

This use case demonstrates how the IMMERSE Wallet, Issuer, and Verifier components communicate to manage identity and access control within immersive learning environments. Soecifically, it presents how a university issues Verifiable Credentials (VCs) to students and how those credentials enable access to virtual or augmented (XR) classrooms using Selective Disclosure JSON Web Tokens (SD-JWT) for privacy-preserving authentication.

## Actors and Roles

* **Issuer (University):** Issues student VCs containing attributes such as *university*, *studentId*, *enrollmentStatus*, and optionally *major* or *courses*.
* **Holder (Student / IMMERSE Wallet):** Receives, stores, and manages VCs, and generates selective Verifiable Presentations (VPs) upon request.
* **Verifier (IMMERSE Verifier):** Requests VPs based on a defined access policy and validates their authenticity before granting entry to an XR classroom.

## Use Case Scenario Description

When a student enrolls, the university issues a VC to their **IMMERSE Wallet**. This credential includes attributes such as the university name, a unique student ID, the student's enrollment status, fullname etc.

When the student later attempts to access a virtual classroom, the **IMMERSE Verifier** requests a VP. The Wallet displays which credential attributes are required for access and lets the student decide what to disclose. If the student omits a required claim, verification fails, otherwise, if all required attributes are included, access is granted.

The exchange uses the OpenID for Verifiable Presentations (OID4VP) protocol, and the Verifier requests VPs that contain certain ayyributes through the Presentation Definition. The Presentation Definition lists which claims are required and which are optional. The Wallet constructs a VP that includes the corresponding disclosures for each attribute the user chose to disclose, while keeping other data hidden.

## Example Credential

We consider *Jane Johnson*, a Computer Science student at the Technical University. Jane's credential includes the following fields:

| Attribute            | Example Value                 | Description                                                          |
| -------------------- | ----------------------------- | -------------------------------------------------------------------- |
| `studentId`          | `S1234567`                    | Unique student identifier (SD-JWT disclosure).          |
| `enrollmentStatus`   | `full-time`                   | Current enrollment state (SD-JWT disclosure).                |
| `fullName`           | `Jane Johnson`                | Student's legal name (SD-JWT disclosure, personalization).                 |
| `major`              | `Computer Science`            | Program/field of study.                   |
| `courses`            | `["CS101","CS202","MATH301"]` | Current/registered courses (SD-JWT disclosure, array disclosed as one claim). |
| `enrollmentDate`     | `2023-09-01`                  | Enrollment start date.                             |
| `expectedGraduation` | `2027-06-15`                  | Anticipated graduation date.                       |

The credential is issued as an SD-JWT VC. Sensitive claims are represented as cryptographic digests (`_sd` values) and are revealed only when the corresponding disclosure objects are included during presentation.

We also provide the following example in JSON format:

```json
{
  "header": {
    "alg": "ES256",
    "typ": "dc+sd-jwt",
    "kid": "issuer-vc-issuer-5bb5db6677-s5vm6-1761814163690"
  },
  "payload": {
    "iss": "https://5fe5a272cdc7.ngrok-free.app",
    "iat": 1761814453,
    "exp": 1793350453,
    "jti": "urn:vc:ed1035b47ada401ce6a6bbe9ee78b4fc",
    "vct": "UniversityDegreeCredential",
    "vc": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": [
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "credentialSubject": {
        "id": "urn:example:student:S1234567",
        "university": "Technical University",
        "_sd": [
          "zp5nOlCGQYj71kSkvJxaTb7Hgln6uoGceE-9OSVnPWw",
          "RGdcxmd0mel0N5gfkW7b9mrwo8a87MAkNvssBM0BJA4",
          "gAqbNGNHhPamO-IfBO2AUe4vfBjRzNEwkoK9ueUW4kw",
          "HN11t350WX2jSleuuk0qXo1AvdatfpBGUuheUjuy9Xk",
          "R85Tb6p51UFK9EUl7iyii3CKcTf-gbXxa2bhj7w9ezA",
          "AntlF5xavrpKgJX8JIV_r4F-CBvozZbzYoKYio2ZhrA",
          "gaBCiAqjm1_hjA7x6_Osp5E1XcJk3bWcmVdr4M8P1z4"
        ],
        "_sd_alg": "sha-256"
      },
      "credentialStatus": {
        "id": "https://5fe5a272cdc7.ngrok-free.app/.well-known/credential-status.json",
        "type": "StatusList2025",
        "statusPurpose": "revocation"
      }
    },
    "cnf": {
      "jwk": {
        "kty": "EC",
        "x": "IJTHK59rCyVPVIJmqUHoM8l8Lo5z1uow7dPbr5jabZw",
        "y": "Jsa2sFazA5sp7_9bGW_tM7ItYUxMuzdRszbf6OJJXIk",
        "crv": "P-256"
      }
    }
  }
}
```

Note that the credential uses the updated `typ` header value `dc+sd-jwt` as defined in the latest *IETF draft-ietf-oauth-sd-jwt-vc*. Earlier versions used `vc+sd-jwt`, both are currently accepted during the transition period.

## Verifier's Presentation Definition Example

The Verifier defines a Presentation Definition specifying which attributes are required for classroom access:

```json
{
  "presentation_definition": {
    "id": "virtual_classroom_access",
    "purpose": "Verify your enrollment status for classroom access",
    "format": {
      "dc+sd-jwt": { "alg": ["ES256"] },
      "vc+sd-jwt": { "alg": ["ES256"] },
      "jwt_vc":    { "alg": ["ES256"] }
    },
    "input_descriptors": [
      {
        "id": "student_identification",
        "purpose": "Verification of student ID",
        "constraints": {
          "fields": [
            {
              "path": ["$.vc.credentialSubject.studentId"],
              "filter": { "type": "string" }
            }
          ]
        }
      },
      {
        "id": "enrollment_status",
        "purpose": "Verification of student enrollment status",
        "constraints": {
          "fields": [
            {
              "path": ["$.vc.credentialSubject.enrollmentStatus"],
              "filter": { "type": "string", "pattern": "full-time|part-time" }
            }
          ]
        }
      }
    ]
  }
}
```

The three attributes: `university`, `studentId`, and `enrollmentStatus`, form the set of attributes that is necessary to verify that a student is allowed to access university-hosted XR classrooms in this example. These attributes let the Verifier confirm that the credential comes from the university, belongs to a valid student, and that the student is currently enrolled as a full time or part time student, for instance, during the first week of the semester when all active students can access XR classrooms to choose their courses.

## References

1. **W3C Verifiable Credentials Data Model v2.0**
   *W3C Candidate Recommendation Snapshot, 2024.*
   [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)

2. **Selective Disclosure for JWTs (SD-JWT)**
   *IETF OAuth Working Group, draft-ietf-oauth-selective-disclosure-jwt-12, July 2024.*
   [https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)

3. **Selective Disclosure JWT-based Verifiable Credentials (SD-JWT VC)**
   *IETF OAuth Working Group, draft-ietf-oauth-sd-jwt-vc-11, November 2024.*
   [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)

4. **OpenID for Verifiable Credential Issuance (OID4VCI)**
   *OpenID Foundation Final Specification, May 2024.*
   [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)

5. **OpenID for Verifiable Presentations (OID4VP)**
   *OpenID Foundation Final Specification, May 2024.*
   [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)

6. **Presentation Exchange 2.0**
   *Decentralized Identity Foundation (DIF), Working Draft, 2023.*
   [https://identity.foundation/presentation-exchange/](https://identity.foundation/presentation-exchange/)
