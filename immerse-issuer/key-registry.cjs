/*
 * Central Key Registry (supporting microservice)
 *
 * A simple, centralized directory where multiple issuers can POST their
 * public JWKs and where relying parties can GET an ecosystem-level aggregate list of keys.
 * This is not the Issuer Metadata endpoint.
 *
 * Relation to specs:
 * - RFC 7517 / RFC 7518: The registry publishes a JSON Web Key Set (JWKS) with
 *   EC P-256 public keys (alg=ES256, use="sig"). 
 * - RFC 7638 (JWK Thumbprint): This service does not compute or enforce thumbprints 
 *   (the base64url-encoded JWK Thumbprint value as a "kid" (key ID) value) it just stores what it receives.
 * - OID4VCI 1.0: Issuers commonly expose their own JWKS/metadata on the issuer's
 *   host. This registry is a supporting component for discovery in our demo,
 *   not a requirement of OID4VCI. It does not claim to satisfy the issuer's
 *   metadata or encryption JWKS parameters.
 *
 * Important behaviors/limitations of this implementation:
 * 1) Storage model: keys are stored by kid (Map<kid, { publicKey, issuer, registeredAt }>).
 *    If two issuers submit the same 'kid', the last write wins.
 * 2) Aggregate JWKS: GET /.well-known/jwks.json returns a single list of keys
 *    across all issuers, filtered to the last 48 hours. This is convenient
 *    for demos but can break verification for older, still-valid artifacts 
 *    and SHOULD be changes for production. Note that IMMERSE Issuers' keys 
 *    rotate on (re)deploy in the demo, the registry keeps a 48h view  of all 
 *    registered keys to avoid stale entries. This window is an implementation 
 *    choice of the registry (for freshness, and smaller payloads) and is 
 *    independent of each issuer's key lifecycle. 
 * 3) No private-key filtering: The service assumes submitted JWKs are public-only.
 *    If a client accidentally includes private members (e.g., 'd'), the service
 *    does not strip or reject them. Operators MUST ensure only public JWKs are sent. 
 *    This SHOULD be changed for production.
 * 4) No authentication/authorization: Any caller can register keys. This is a
 *    trusted/demo component, not a hardened key directory/key management microservice.
 * 5) Well-known path: Exposing /.well-known/jwks.json on the registry host
 *    is not equivalent to the issuer's own JWKS. In this demo, it is deliberately
 *    an aggregate registry JWKS, not an issuer JWKS.
 */


const express = require('express');
const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());

// In-memory storage for issuer keys
// Structure: Map<kid, { publicKey, issuer, registeredAt }>
const keyDatabase = new Map();

/**
 * POST /register
 * Registers (or updates) a public key entry.
 *
 * Request body shape:
 *   { kid: string, publicKey: <public JWK>, issuer: string }
 *
 * Keys are stored by 'kid' globally (not per-issuer). Last write wins on collision.
 * 'registeredAt' is set and used later for the 48h filter in the JWKS export.
 */
app.post('/register', (req, res) => {
  const { kid, publicKey, issuer } = req.body;
  
  keyDatabase.set(kid, {
    publicKey,
    issuer,
    registeredAt: Date.now()
  });
  
  console.log(`Registered key: ${kid} from ${issuer}`);
  res.status(201).send({ status: 'registered' });
});

/**
 * Discovery - GET /.well-known/jwks.json
 * Returns an aggregate JWKS for the registry (NOT an issuer's JWKS).
 * Iterates over all stored keys (by kid).
 * Keeps only entries whose `registeredAt` is within the last 48 hours.
 * JWKs with `kid`, `use: "sig"`, `alg: "ES256"`.
 */
app.get('/.well-known/jwks.json', (req, res) => {
  const validKeys = [];
  const now = Date.now();
  
  for (const [kid, keyData] of keyDatabase.entries()) {
    // Only include keys from the last 48 hours
    if (now - keyData.registeredAt < 48 * 60 * 60 * 1000) {
      validKeys.push({
        ...keyData.publicKey,
        kid,
        use: 'sig',
        alg: 'ES256'
      });
    }
  }
  
  res.json({ keys: validKeys });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Key registry running on port ${port}`);
});
