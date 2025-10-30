# Revoked and Expired Credentials

Revocation in the IMMERSE ecosystem is implemented as follows: credentials are never deleted from the wallet but are instead marked as revoked by the issuer. Each credential contains a `status_endpoint` pointing to the issuer's `.well-known/credential-status.json` list. When a Verifier receives a Verifiable Presentation, it checks the credential's `jti` (unique identifier) against that list to determine if it has been revoked.

Revocation is performed manually or automatically by the IMMERSE Issuer through an endpoint, i.e. `/admin/revoke`. The revocation list is updated immediately and can be queried through its public endpoint.

## Table of Contents

- [Revoked and Expired Credentials](#revoked-and-expired-credentials)
  - [Verifiable Credential Revocation](#verifiable-credential-revocation)
    - [Revocation through Ngrok](#revocation-through-ngrok)
  - [Verifiable Credential Expiration Checks](#verifiable-credential-expiration-checks)
    - [Implementation Summary](#implementation-summary)
  - [References](#references)

## Verifiable Credential Revocation

### Revocation through Ngrok

To view expired VCs:

```bash
curl <ISSUER_URL>/.well-known/credential-status.json | jq
```

Expect to see the following (if no credentials have been revoked):

```bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   164  100   164    0     0    514      0 --:--:-- --:--:-- --:--:--   515
{
  "issuer": "https://5fe5a272cdc7.ngrok-free.app",
  "updated_at": "2025-10-30T08:58:14.643Z",
  "type": "StatusList2025",
  "statusPurpose": "revocation",
  "revoked": []
}
```

To revoke a VC:

```bash
curl -X POST <ISSUER_URL>/admin/revoke \
     -H "Content-Type: application/json" \
     -d '{"jti":"urn:vc:ed1035b47ada401ce6a6bbe9ee78b4fc"}'
```

Example response:

```bash
{"revoked":"urn:vc:ed1035b47ada401ce6a6bbe9ee78b4fc","total_revoked":1}
```

Verify it has been revoked with:

```bash
curl <ISSUER_URL>/.well-known/credential-status.json | jq
```

Output will now include the revoked credential identifier:

```bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   226  100   226    0     0    659      0 --:--:-- --:--:-- --:--:--   660
{
  "issuer": "<ISSUER_URL>",
  "updated_at": "2025-10-30T09:02:34.701Z",
  "type": "StatusList2025",
  "statusPurpose": "revocation",
  "revoked": [
    "urn:vc:ed1035b47ada401ce6a6bbe9ee78b4fc"
  ]
}
```

To find and view wallet logs for revoked VCs:

```bash
kubectl logs wallet-backend-XXXX -n=cvm-wallets
```

where you can find the pod name with:

```bash
kubectl get po -n=cvm-wallets
```

Wallet logs for a revoked credential presentation will show:

```bash
SD-JWT length: 2180
Number of selected disclosures: 2
Selected disclosures: [
  'WyItZUNpMXJjZkFScUhVNE1mT1JXVElBIiwic3R1ZGVudElkIiwiUzEyMzQ1NjciXQ',
  'WyI2QzZRdTZEWk1XQ3pwOHk1eWhPX29nIiwiZW5yb2xsbWVudFN0YXR1cyIsImZ1bGwtdGltZSJd'
]
VP Token created: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsIngiOiJJSlRISzU5ckN5VlBWSUptcVVIb004bDhM...
```

and

```bash
{...
{...
  {...
    {...
    },
    data: {
      error: 'verification_failed',
      message: 'revocation_check_failed'
    }
  },
  status: 400
}
Verifier response: { error: 'verification_failed', message: 'revocation_check_failed' }
```

## Verifiable Credential Expiration Checks

The IMMERSE Wallet includes expiration checks in the wallet backend. Each credential is issued with a JWT `exp` claim, representing its validity period in seconds since epoch. The wallet backend automatically removes expired credentials without requiring user intervention.

### Implementation Summary

The wallet reads the first part of the SD-JWT and decodes the payload to extract the `exp` value. Expired credentials are removed:

- Immediately upon retrieval from the issuer if already expired.
- Before any listing (GET `/credentials`).
- Periodically through a background cleanup function (default: every 60 minutes).

Before generating a Verifiable Presentation, the wallet also checks for expiration and blocks the use of expired credentials.

Example Log Output:

```text
[wallet] Purged 1 expired credential(s) for session wallet-session-YYY
[wallet] Received an already-expired credential; not storing.
```

This approach follows the IETF and OpenID specifications for SD-JWT and DC+SD-JWT credentials, which rely on standard JWT time-based validity. It is fully compliant with the current drafts of SD-JWT VC and the Token Status List (TSL) draft, where expiration is managed by the holder wallet, while revocation checks are the responsibility of verifiers. This design also aligns with the EU Digital Wallet Architecture and Reference Framework, which discourages wallet-side revocation polling to avoid unnecessary network load and correlation risks, while still enforcing `exp` based credential validity automatically.

## References

1. **SD-JWT VC Draft (IETF)** - *Selective Disclosure JWT-based Verifiable Credentials*,  
   [https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)

2. **Token Status List Draft (IETF)** - *Status List for Verifiable Credentials*,  
   [https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)

3. **EU Digital Wallet ARF** - *European Digital Identity Wallet Architecture and Reference Framework (ARF)*,  
   [https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework](https://digital-strategy.ec.europa.eu/en/library/european-digital-identity-wallet-architecture-and-reference-framework)
