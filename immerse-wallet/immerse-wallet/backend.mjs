// wallet_backend.mjs  -use any Node version that is 18++
/**
 * IMMERSE Wallet Backend (OID4VCI + OID4VP)
 *
 * Purpose: Holder-operated "cloud wallet" that (1) accepts credential offers,
 * (2) obtains SD-JWT VCs from the Issuer, (3) stores them, and (4) generates
 * Verifiable Presentations for Verifiers.
 *
 * Standards implemented:
 * - OpenID for Verifiable Credential Issuance (OID4VCI) 1.0
 *   Token: pre-authorized_code grant (sec. 6.1)
 *   Credential: proof.jwt with typ=openid4vci-proof+jwt (App. F)
 * - OpenID for Verifiable Presentations (OID4VP) 1.0
 *   Request by reference (request_uri) + response_mode=direct_post (sec. 5/8)
 *   presentation_submission object (sec. 6)
 * - SD-JWT VC draft (draft-ietf-oauth-sd-jwt-vc-12)
 *   Media type typ=dc+sd-jwt (accept legacy vc+sd-jwt)
 *   Disclosures hashed via _sd / _sd_alg=sha-256
 * OAuth 2.0 Attestation-Based Client Authentication (ABCA)
 *   draft-ietf-oauth-attestation-based-client-auth-07
 *   Wallet sends:
 *   - client-attestation-pop: Proof-of-Possession JWT signed by the CI-Key
 *       (the Attestation Proof Key) with the /token audience. Demonstrates
 *       that the wallet possesses the same key attested in client-attestation.
 *   - client-attestation: Attestation JWT that contains the CI-Key, anchoring
 *       it to the device/TEE root (A-Key) and optionally binding the derived
 *       Holder key used later in OID4VCI proof and OID4VP presentations.
 *
 * Operational model:
 * - Runs in a Confidential VM (AMD SEV) as part of IMMERSE demo.
 * - Uses a local Attestation Service (CVM level in this implementation).
 * - A-Key material is held in SoftHSM (mounted PVC) scoped via K8s RBAC/NetworkPolicies.
 * 
 * Security consideration notes:
 * - We prefer JSON for internal APIs but honor spec-required encodings:
 *   application/x-www-form-urlencoded for /token body and direct_post responses.
 *   application/json for request objects and metadata.
 * - Nonce/state from Issuer/Verifier are always used to prevent replay.
 * - Holder-binding through cnf.jwk.
 * - SD-JWT verification uses salted disclosure digests (_sd) before storage/presentation.
 * - Keys are rotated on schedule, but long-lived roots (A-Key) are isolated in CVM + SoftHSM.
 * - see more in security-doc.md
 *
 */

import express from 'express';
import { SignJWT, jwtVerify, exportJWK } from 'jose';
import crypto from 'crypto';
import base64url from 'base64url';
import axios from 'axios';
import { URL } from 'url'; // added at oid4vp phase
import { URLSearchParams } from 'url';
import cors from 'cors'; // cors error - FRONTEND
import fs from 'fs';
import * as http from 'http';
import * as https from 'https';

/**
 * Configuration / Environment
 *
 * Reads Issuer and Verifier URLs, plus any demo flags, from env.
 * These values are NOT secrets, they are routing/config. Secrets (if any)
 * should be injected via Kubernetes Secrets or vault, not in images.
 *
 * K8s note: Services and Deployments for this wallet mirror the issuer/verifier
 * pattern used elsewhere (logging, readiness/liveness probes), see more in wallet-doc. 
 */

const app = express();
const port = 4000;

const ALLOWED = (process.env.CORS_ALLOW_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

const NGROK_RE = /^https?:\/\/([a-z0-9-]+\.)?ngrok(-free)?\.(app|dev)$/i;

// implementation specific patterns
function isAllowedOrigin(origin) {
  if (!origin) return true;              
  if (ALLOWED.includes('*')) return true;
  if (ALLOWED.includes(origin)) return true;
  if (NGROK_RE.test(origin)) return true;
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin)) return true;
  if ("ADD CVM IP HERE OR COMMENT THIS LINE") return true;   // CVM IP
  if ("ADD MINIKUBE IP HERE OR COMMENT THIS LINE") return true; // minikube IP
  return false;
}

app.use(cors({
  origin: (origin, cb) => isAllowedOrigin(origin) ? cb(null, true) : cb(new Error('CORS: origin not allowed')),
  credentials: false,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Client-Attestation','Client-Attestation-PoP']
}));

app.use(express.json());

// EXPIRED UPDATES
function parseJwtPayload(jwtOrSdJwt) {
  const jwt = jwtOrSdJwt.includes('~') ? jwtOrSdJwt.split('~')[0] : jwtOrSdJwt;
  const [, payloadB64] = jwt.split('.');
  return JSON.parse(base64url.decode(payloadB64));
}

function isExpiredCredential(jwtOrSdJwt, nowSec = Math.floor(Date.now() / 1000)) {
  try {
    const p = parseJwtPayload(jwtOrSdJwt);
    return typeof p.exp === 'number' && p.exp < nowSec;
  } catch {
    // If we cannot parse, treat as not-expired (fail-open on parsing only)
    return false;
  }
}

function purgeExpiredCredentials(session) {
  if (!session?.credentials?.length) return;
  const before = session.credentials.length;
  session.credentials = session.credentials.filter(c => !isExpiredCredential(c));
  const after = session.credentials.length;
  if (before !== after) {
    console.log(`[wallet] Purged ${before - after} expired credential(s) for session ${session.userId}`);
  }
}
// EXPIRED UPDATES END

// ==== Attestation helpers ====
const ATTESTER_URL = process.env.ATTESTER_URL;              // e.g. http://cvm-attester.cvm-security.svc.cluster.local:5000/attest
const ATTESTER_BEARER = process.env.ATTESTER_BEARER || "";  // optional fallback
const ATTESTER_BEARER_FILE = process.env.ATTESTER_BEARER_FILE || ""; // projected token

// In-cluster SA token (when backend runs inside k8s). For local dev, allow override via env.
function readServiceAccountToken() {
  try {
    // works in-cluster
    return fs.readFileSync('/var/run/secrets/kubernetes.io/serviceaccount/token', 'utf8').trim();
  } catch {
    // local dev fallback
    return process.env.ATT_TEST_BEARER || '';
  }
}

// simple base64url
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// In-memory CI key (EC P-256)
let CI_JWK_PRIV = null;
let CI_JWK_PUB  = null;

async function getOrCreateCIKey() {
  if (CI_JWK_PRIV && CI_JWK_PUB) return { priv: CI_JWK_PRIV, pub: CI_JWK_PUB };

  const { subtle } = globalThis.crypto || (await import('node:crypto')).webcrypto;
  const key = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const jwkPriv = await subtle.exportKey('jwk', key.privateKey);
  const jwkPub  = await subtle.exportKey('jwk', key.publicKey);
  
  jwkPriv.alg = 'ES256'; jwkPriv.key_ops = ['sign']; jwkPriv.use = 'sig';
  jwkPub.alg  = 'ES256'; jwkPub.key_ops  = ['verify']; jwkPub.use  = 'sig';
  CI_JWK_PRIV = jwkPriv; CI_JWK_PUB = jwkPub;
  return { priv: jwkPriv, pub: jwkPub };
}

async function signES256JWS(jwkPriv, payloadObj, headerExtra = {}) {
  const header = { alg: 'ES256', typ: 'JWT', ...headerExtra };
  const payload = payloadObj;
  const encodedHeader  = b64url(Buffer.from(JSON.stringify(header)));
  const encodedPayload = b64url(Buffer.from(JSON.stringify(payload)));
  const signingInput   = Buffer.from(`${encodedHeader}.${encodedPayload}`);

  // Import the private key via WebCrypto
  const { subtle } = globalThis.crypto || (await import('node:crypto')).webcrypto;
  const key = await subtle.importKey(
    'jwk',
    jwkPriv,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const sigBuf = Buffer.from(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, signingInput)
  );

  // Convert to JOSE (r||s) if needed
  const toJose = (der) => {
    // already raw r||s?
    if (der.length === 64) return der;

    // DER -> JOSE
    let b = Buffer.from(der), off = 0;
    if (b[off++] !== 0x30) throw new Error(`Bad DER`);
    // read total len (handle short/long form)
    if (b[off] & 0x80) off += 1 + (b[off] & 0x7f); else off += 1;

    if (b[off++] !== 0x02) throw new Error('Bad DER(r)');
    let rlen = b[off++]; let r = b.slice(off, off + rlen); off += rlen;

    if (b[off++] !== 0x02) throw new Error('Bad DER(s)');
    let slen = b[off++]; let s = b.slice(off, off + slen);

    const trim = (x) => (x[0] === 0x00 ? x.slice(1) : x);
    r = trim(r); s = trim(s);
    if (r.length > 32 || s.length > 32) throw new Error('Component too long');
    r = Buffer.concat([Buffer.alloc(32 - r.length, 0), r]);
    s = Buffer.concat([Buffer.alloc(32 - s.length, 0), s]);
    return Buffer.concat([r, s]);
  };

  const sigJose = toJose(sigBuf);
  return `${encodedHeader}.${encodedPayload}.${b64url(sigJose)}`;
}

/**
 * Build unsigned attestation payload
 * The attester will sign this (A-Key). It includes iss/sub (client_id),
 * aud (issuer base), iat/exp, and cnf.jwk (our CI public JWK).
 */
// Build the **unsigned** attestation payload (attester will sign it with A-Key)
function buildUnsignedAttestation(client_id, aud, ci_jwk) {
  const now = Math.floor(Date.now()/1000);
  return {
    iss: client_id,
    sub: client_id,
    aud,
    iat: now,
    exp: now + 3600,
    cnf: { jwk: ci_jwk }
  };
}

/**
 * Call attestation service
 *
 * POST unsigned payload + SA bearer -> returns Client-Attestation JWT.
 */
// Ask the attester to sign our unsigned attestation
async function fetchAttestationJWT(unsignedPayload, bearer, extra = {}) {
  const body = JSON.stringify({ ...unsignedPayload, ...extra, ci_jwk: unsignedPayload.cnf.jwk, client_id: unsignedPayload.iss });
  const mod = ATTESTER_URL.startsWith('https') ? https : http;

  const xTrace = extra.trace || '';

  return await new Promise((resolve, reject) => {
    const u = new URL(ATTESTER_URL);
    const req = mod.request(
      {
        hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname, method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${bearer}`,
          'X-Trace': xTrace
        }
      },
      (res) => {
        let chunks=''; res.setEncoding('utf8');
        res.on('data',(d)=>chunks+=d);
        res.on('end', () => {
          if (res.statusCode !== 200) {
            return reject(new Error(`attester ${res.statusCode}: ${chunks}`));
          }
          try {
            const { attestation } = JSON.parse(chunks);
            resolve(attestation);
          } catch (e) { reject(e); }
        });
      }
    );
    req.on('error', reject);
    req.write(body); req.end();
  });
}

/**
 * Build Client-Attestation PoP (ES256)
 *
 * Short-lived (~60s) PoP signed by the CI private key. 
 */
async function buildPoP(ciPrivJwk, aud, client_id, challenge) {
  const now = Math.floor(Date.now()/1000);
  const payload = {
    iss: client_id,
    aud: aud,
    iat: now,
    exp: now + 60,
    jti: crypto.randomUUID(),
    ...(challenge ? { challenge } : {})
  };

  // Create public JWK from private JWK (remove private key material)
  const publicJwk = { ...ciPrivJwk };
  delete publicJwk.d;  // Remove the private key component
  delete publicJwk.key_ops; // Remove key operations if present

  return signES256JWS(ciPrivJwk, payload, {
    typ: 'oauth-client-attestation-pop+jwt',
    jwk: publicJwk  // Add the public JWK to header
  });
}

/**
 * Session / State
 *
 * Wallet session state holds:
 * - login/session token for the frontend (demo)
 * - temporary verification sessions (state, nonce, request_uri, definition)
 *
 * These are used to correlate OID4VP requests/responses (nonce/state) and to
 * carry the Verifier's Request Object to the point where the VP is produced.
 * - Fresh nonce is RECOMMENDED and state is REQUIRED in some cases (sec. 5.2/5.3).
 * - Wallet must bind response to the request using these values.
 */
// Secure wallet state (in-memory in SEV VM)
const sessions = new Map();            // session_token --> { userId, keys, credentials }
const pendingVerifications = new Map(); // state --> { sessionToken, nonce, redirectUri, clientId }
const selectivePresentations = new Map(); // credentialIndex --> selectivePresentation

/**
 * Key Material (Holder Key)
 *
 * The wallet generates an EC P-256 key pair for the Holder inside the cVM and
 * keeps the private key in process memory, the public key is exposed as a JWK
 * when building PoP/VP JWTs. This is the key referenced by cnf.jwk in issued
 * credentials and used later for OID4VP presentations.
 * In this code generateKeyPair()` creates { privateKey, publicKey, publicJwk } (ES256).
 * Security note: For the demo we do not persist private keys to disk. In
 * production, store keys in an HSM / OS keyring, enable rotation, and pin
 * algorithms/policies according to your compliance profile.
 */
// Generate key pair inside SEV environment
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });

  // Export the public JWK 
  const publicJwk = publicKey.export({ format: 'jwk' });

  return {
    privateKey,
    publicKey,
    publicJwk
  };
}

// Add cleanup for expired sessions --> UPDATED added at oid4vp phase
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    purgeExpiredCredentials(session); // EXPIRED UPDATES
    if (now - session.createdAt > 24 * 60 * 60 * 1000) { // 24h expiration
      sessions.delete(token);
    }
  }
  for (const [state, verification] of pendingVerifications.entries()) {
    if (now - verification.createdAt > 15 * 60 * 1000) { // 15 min expiration
      pendingVerifications.delete(state);
    }
  }
}, 60 * 60 * 1000); // Run hourly

/**
 * POST /login
 *
 * Establishes a frontend session (demo). No protocol references here, just a
 * way for the UI to obtain a session token and for the backend to initialize
 * holder key material if needed.
 */
// User authentication endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // In production: use secure authentication
  const userId = `anon-${crypto.randomBytes(8).toString('hex')}`;
  const sessionToken = crypto.randomBytes(32).toString('hex');

  sessions.set(sessionToken, {
    userId,
    createdAt: Date.now(),
    keys: null,
    credentials: []
  });

  res.json({ session_token: sessionToken });
});

/**
 * POST /process-offer
 *
 * Purpose: handle OID4VCI credential offers from Issuer.
 * Flow:
 *  1) Parse credential_offer or credential_offer_uri.
 *  2) Use the pre-authorized_code grant at the Issuer's /token (sec. 6.1).
 *  3) Extract c_nonce (server challenge) for proof binding.
 *  4) Build openid4vci-proof+jwt with Holder key (PoP) referencing the c_nonce.
 *  5) POST /credential to obtain the SD-JWT VC (typ=dc+sd-jwt).
 *  6) Store the VC in wallet storage for later presentation.
 * - /token uses application/x-www-form-urlencoded per spec.
 *
 * Interop note:
 * - The IMMERSE issuer accepts both dc+sd-jwt and (legacy) vc+sd-jwt- we store the VC as
 *   "JWT~disclosure1~disclosure2~...". 
 */
// Process credential offer 
app.post('/process-offer', async (req, res) => {
  // Get session token from Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_authorization' });
  }
  const sessionToken = authHeader.split(' ')[1];
  const session = sessions.get(sessionToken);

  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }

  const { credentialOfferUri } = req.body;
  if (!credentialOfferUri) {
    return res.status(400).json({ error: 'missing_credential_offer_uri' });
  }

  try {
    // Proper URL parsing with dummy base for custom schemes
    const url = new URL(credentialOfferUri, 'http://dummy-base');
    const offerParam = url.searchParams.get('credential_offer');

    if (!offerParam) {
      throw new Error('Missing credential_offer parameter');
    }

    const decoded = base64url.decode(offerParam);
    const credentialOffer = JSON.parse(decoded);

    // Handle different grant types
    if (credentialOffer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      // Pre-authorized flow
      const result = await handlePreAuthorizedFlow(session, credentialOffer);
      res.json(result);
    } else {
      res.status(400).json({ error: 'unsupported_grant_type' });
    }
  } catch (error) {
    console.error('Offer processing failed:', error);
    res.status(400).json({
      error: 'invalid_offer',
      message: error.message
    });
  }
});

// sd-jwt updates
/**
 * POST /create-selective-presentation
 * Builds a SD-JWT by keeping only user-chosen disclosures.
 * Stores the selective string in-memory for later submission.
 */
app.post('/create-selective-presentation', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_authorization' });
  }

  const sessionToken = authHeader.split(' ')[1];
  const session = sessions.get(sessionToken);

  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }

  const { sdJwt, disclosures, credentialIndex } = req.body;

  console.log('Creating selective presentation for credential:', credentialIndex);
  console.log('SD-JWT length:', sdJwt.length);
  console.log('Number of selected disclosures:', disclosures.length);
  console.log('Selected disclosures:', disclosures);

  if (!sdJwt || !disclosures || credentialIndex === undefined) {
    return res.status(400).json({ error: 'missing_parameters' });
  }

  try {
    // Parse the SD-JWT
    const parts = sdJwt.split('~');
    const jwt = parts[0];
    const allDisclosures = parts.slice(1);

    // Filter to only include the selected disclosures
    const selectedDisclosureDigests = disclosures.map(d => {
      return base64url.encode(crypto.createHash('sha256').update(d).digest());
    });

    // Create a new SD-JWT with only the selected disclosures
    const selectiveSdJwt = [jwt, ...disclosures].join('~');

    // Store the selective presentation
    selectivePresentations.set(parseInt(credentialIndex), selectiveSdJwt);

    res.json({
      presentation: selectiveSdJwt,
      disclosed_claims: disclosures.map(d => {
        const disclosure = JSON.parse(base64url.decode(d));
        return { claim: disclosure[1], value: disclosure[2] };
      })
    });
  } catch (error) {
    console.error('Error creating selective presentation:', error);
    res.status(400).json({
      error: 'presentation_creation_failed',
      message: error.message
    });
  }
});

// Handle pre-authorized code flow 
// issuer advertises endpoints in metadata: fetch metadata first and use
async function handlePreAuthorizedFlow(session, credentialOffer) {

  // ---- TIMING BEGIN ----
  const trace = `tr_${crypto.randomBytes(6).toString('hex')}`;
  const T = {};
  const now = () => Date.now();
  T.t_offer_recv = now();
  console.log(`[timing][wallet][${trace}] offer_recv`);

  // --- build token URL dynamically from the offer ---
  const tokenUrl = new URL('/token', credentialOffer.credential_issuer).toString();
  const issuerBase = credentialOffer.credential_issuer;
  console.log(issuerBase);

  // --- Client Instance key (CI-Key) for PoP / cnf.jwk (generate once) ---
  const { priv: ciPriv, pub: ciPub } = await getOrCreateCIKey();

  // --- stable client_id ---
  const client_id = 'urn:wallet:' + session.userId;

  // --- SA bearer for TokenReview at attester (works in K8s; empty locally unless ATT_TEST_BEARER is set) ---
  const saBearer = readServiceAccountToken();

  // 1) unsigned attestation payload (issuer == client_id; includes cnf.jwk)
  const unsignedAtt = buildUnsignedAttestation(client_id, issuerBase, ciPub);

  T.t_attest_req = now();
  console.log(`[timing][wallet][${trace}] attest_req`);

  // 2) ask attester to sign with A-Key -> Client-Attestation JWT
  //const clientAttestation = await fetchAttestationJWT(unsignedAtt, saBearer);
  const clientAttestation = await fetchAttestationJWT(unsignedAtt, saBearer, { trace });

  T.t_attest_res = now();
  console.log(`[timing][wallet][${trace}] attest_res dur=${T.t_attest_res - T.t_attest_req}ms`);


  // 3) PoP signed by CI-Key, audience = token endpoint
  const clientPoP = await buildPoP(ciPriv, tokenUrl, client_id);
  //const clientPoP = await buildPoP(ciPriv, issuerBase, client_id);

  T.t_pop_done = now();
  console.log(`[timing][wallet][${trace}] pop_done`);


  // 4) call /token with form-urlencoded body + required headers
  const grant = credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
  const preAuthorizedCode = grant['pre-authorized_code'];

  const form = new URLSearchParams();
  form.set('grant_type', 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
  form.set('pre_authorized_code', preAuthorizedCode);
  
  form.set('client_id', client_id);

  T.t_token_req = now();
  console.log(`[timing][wallet][${trace}] token_req url=${tokenUrl}`);

  const tokenResponse = await axios.post(
    tokenUrl,
    form.toString(),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Client-Attestation': clientAttestation,
        'Client-Attestation-PoP': clientPoP,
        'X-Trace': trace
      }
    }
  );

  T.t_token_res = now();
  console.log(`[timing][wallet][${trace}] token_res dur=${T.t_token_res - T.t_token_req}ms`);

  // Generate keys in SEV environment if not already done
  if (!session.keys) {
    session.keys = generateKeyPair();
  }
  const keyPair = session.keys;

  T.t_issue_req = now();
  console.log(`[timing][wallet][${trace}] issue_req`);

  // Get credential
  const credential = await requestCredential(
    credentialOffer.credential_issuer,
    tokenResponse.data.access_token,
    tokenResponse.data.c_nonce,
    keyPair,
    trace
  );

  T.t_issue_res = now();
  console.log(`[timing][wallet][${trace}] issue_res dur=${T.t_issue_res - T.t_issue_req}ms`);


  console.log("Credential received from issuer:", credential ? "Present" : "Missing");

  // EXPIRED UPDATES
  // skip storing if already expired (just in case)
  if (isExpiredCredential(credential)) {
    console.warn('[wallet] Received an already-expired credential; not storing.');
    return { status: 'credential_expired', credential }; // still return so UI can show why it's not stored
  }

  // quick purge before we add
  purgeExpiredCredentials(session);
  // EXPIRED UPDATES END

  session.credentials.push(credential);
  console.log("Credential added to session. Total credentials:", session.credentials.length);

  return { status: 'credential_issued', credential };
}

// Request credential from issuer
//async function requestCredential(issuerUrl, accessToken, cNonce, keyPair) {
async function requestCredential(issuerUrl, accessToken, cNonce, keyPair, trace) {
  // Create PoP token (RFC 7800 compliant)
  console.log('Key type:', keyPair.privateKey.type); // Should log: 'private' // DEBUG

  const popToken = await new SignJWT({
    nonce: cNonce,
    jti: crypto.randomBytes(16).toString('hex'),
    iss: 'wallet-backend',
    aud: issuerUrl,
    iat: Math.floor(Date.now() / 1000)
  })
  .setProtectedHeader({
    alg: 'ES256',
    typ: 'openid4vci-proof+jwt' // Fixed type per spec
  })
  .sign(keyPair.privateKey); // sign with w sk

  // Look up supported credential types
  const metadata = await getIssuerMetadata(issuerUrl, trace);

  // Prefer vct, fallback to types for legacy issuers
  const first = metadata.credential_configurations_supported?.[0] || {};
  const credentialType = first.vct || (Array.isArray(first.types) ? first.types.find(t => t !== 'VerifiableCredential') : undefined) || 'UniversityDegreeCredential';


  console.log("---- DEBUG WALLET ----"); // DEBUG
  console.log("Access Token:", accessToken);
  console.log("c_nonce:", cNonce);
  console.log("Public JWK:", JSON.stringify(keyPair.publicJwk, null, 2));
  console.log("PoP JWT Payload:", {
    nonce: cNonce,
    jti: 'random',
    aud: issuerUrl,
    iat: Math.floor(Date.now() / 1000)
  });
  console.log("PoP JWT:", popToken);
  console.log("----------------------");

  let body = {
    format: 'dc+sd-jwt',
    vct: credentialType,
    proof: {
      proof_type: 'jwt',
      jwt: popToken,
      public_key_jwk: keyPair.publicJwk
    }
  };
  let credentialResponse;
  try {
    credentialResponse = await axios.post(
      `${issuerUrl}/credential`,
      body,
      { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'X-Trace': trace } }
    );
  } catch (e) {
    // Backward-compat
    if (e.response?.status === 400 || e.response?.status === 415) {
      body = { ...body, format: 'vc+sd-jwt' };
      delete body.vct; // some legacy servers only accept 'types'
      body.types = ['VerifiableCredential', credentialType];
      credentialResponse = await axios.post(
        `${issuerUrl}/credential`,
        body,
        { headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'X-Trace': trace } }
      );
    } else {
      throw e;
    }
  }


  return credentialResponse.data.credential;
}

// Get issuer metadata
//async function getIssuerMetadata(issuerUrl) {
async function getIssuerMetadata(issuerUrl, trace) {
  const response = await axios.get(
    `${issuerUrl}/.well-known/openid-credential-issuer`,
    //{ headers: { Accept: 'application/json' } },
    { headers: { Accept: 'application/json', 'X-Trace': trace } }
  );
  return response.data;
}

// Get stored credentials
/**
 * GET /credentials
 *
 * Returns the wallet's stored credentials to demonstrate to the user.
 * This is internal to the demo and not part of OID4VCI/VP protocols.
 */
app.get('/credentials', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_authorization' });
  }
  const sessionToken = authHeader.split(' ')[1];
  const session = sessions.get(sessionToken);

  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }
  // EXPIRED UPDATES -> LINE FOR THE UI so that we dont show exp
  purgeExpiredCredentials(session);

  res.json({ credentials: session.credentials });
});

function extractRequestedFields(presentationDefinition) {
  const requestedFields = [];

  presentationDefinition.input_descriptors.forEach(descriptor => {
    descriptor.constraints.fields.forEach(field => {
      // Extract the field path 
      const path = field.path[0];
      const fieldName = path.split('.').pop();

      // Check if field is required based on purpose or other indicator
      const isRequired = field.purpose && field.purpose.toLowerCase().includes('required');

      requestedFields.push({
        name: fieldName,
        purpose: field.purpose || 'Verification',
        required: isRequired
      });
    });
  });

  return requestedFields;
}

/**
 * OID4VP: process presentation request (request_uri)
 *
 * Accepts an openid:// (or HTTPS) request_uri, gets the Request Object,
 * parses response_type=vp_token, response_mode=direct_post, nonce, state,
 * and presentation_definition. Stores a pending verification keyed by state.
 */
// Handle OID4VP presentation requests -- for VR learning use case
app.post('/process-presentation-request', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_authorization' });
  }
  const sessionToken = authHeader.split(' ')[1];
  const session = sessions.get(sessionToken);

  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }

  const { requestUri } = req.body;
  if (!requestUri) {
    return res.status(400).json({ error: 'missing_request_uri' });
  }

  try {
    // Parse the request URI
    let presentationRequest;
    if (requestUri.startsWith('openid://')) {
      const url = new URL(requestUri.replace('openid://', 'http://dummy/'));
      const requestUriParam = url.searchParams.get('request_uri');

      if (!requestUriParam) {
        throw new Error('Missing request_uri parameter');
      }

      const requestResponse = await axios.get(requestUriParam);
      presentationRequest = requestResponse.data;
    } else {
      const requestResponse = await axios.get(requestUri);
      presentationRequest = requestResponse.data;
    }

    // Extract requested fields from presentation definition
    const requestedFields = extractRequestedFields(presentationRequest.presentation_definition);

    // Store verification session with requested fields
    pendingVerifications.set(presentationRequest.state, {
      sessionToken,
      nonce: presentationRequest.nonce,
      redirectUri: presentationRequest.response_uri,
      clientId: presentationRequest.client_id,
      presentationDefinition: presentationRequest.presentation_definition,
      requestedFields: requestedFields, // Store requested fields
      createdAt: Date.now()
    });

    // Check if we have matching credentials
    const matchingCredentials = session.credentials.filter(credential => {
      try {
        // For SD-JWT, take the first part before '~'
        const jwtPart = credential.includes('~') ? credential.split('~')[0] : credential;
        const parts = jwtPart.split('.');
        const payload = JSON.parse(base64url.decode(parts[1]));

        // Check for 'UniversityDegreeCredential' type
        //if (payload.vc && payload.vc.type) {
        // Accept either vct or vc.type
        if (payload.vct) {
          return payload.vct === 'UniversityDegreeCredential';
        } else if (payload.vc && payload.vc.type) {
          if (Array.isArray(payload.vc.type)) {
            return payload.vc.type.includes('UniversityDegreeCredential') ||
               payload.vc.type.includes('VerifiableAttestation');
          } else {
            return payload.vc.type === 'UniversityDegreeCredential' ||
               payload.vc.type == 'VerifiableAttestation';
          }
        }
        return false;
      } catch (e) {
        console.error('Error parsing credential:', e);
        return false;
      }
    });

    res.json({
      request: presentationRequest,
      matching_credentials: matchingCredentials,
      requested_fields: requestedFields, // Include requested fields in response
      state: presentationRequest.state
    });
  } catch (error) {
    console.error('Presentation request processing failed:', error);
    res.status(400).json({
      error: 'invalid_request',
      message: error.message
    });
  }
});

/**
 * POST /submit-presentation
 *
 * Builds a vp_token (JWT) embedding a W3C VP
 * Sends { vp_token, state, presentation_submission }
 * to the verifier's response_uri (OID4VP direct_post).
 *
 * presentation_submission maps the chosen credential to each input_descriptor.
 */
// Update the submit-presentation endpoint to handle sd
app.post('/submit-presentation', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_authorization' });
  }

  const sessionToken = authHeader.split(' ')[1];
  const session = sessions.get(sessionToken);

  if (!session) {
    return res.status(401).json({ error: 'invalid_session' });
  }

  const { state, credentialIndex = 0, useSelectivePresentation = false } = req.body;

  if (!state) {
    return res.status(400).json({ error: 'missing_state' });
  }

  const verification = pendingVerifications.get(state);
  if (!verification) {
    return res.status(400).json({ error: 'invalid_state' });
  }

  const trace = `tr_${crypto.randomBytes(6).toString('hex')}`;
  const now = () => Date.now();
  const T = {};

  try {
    // Get the selected credential
    let selectedCredential;
    if (useSelectivePresentation && selectivePresentations.has(credentialIndex)) {
      selectedCredential = selectivePresentations.get(credentialIndex);
    } else {
      if (credentialIndex >= session.credentials.length) {
        return res.status(400).json({ error: 'invalid_credential_index' });
      }
      selectedCredential = session.credentials[credentialIndex];
    }

    T.t_vp_pop_start = now();            // start signing the VP (holder PoP)

    // Create VP token with the correct nonce from the verification request
    const vpToken = await new SignJWT({
      nonce: verification.nonce, // Use the nonce from the verification request
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [selectedCredential]
      }
    })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'JWT',
      jwk: session.keys.publicJwk
    })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(session.keys.privateKey);

    T.t_vp_pop_end = now();
    console.log(`[timing][wallet][${trace}] vp_pop_sign dur=${T.t_vp_pop_end - T.t_vp_pop_start}ms`);

    console.log("VP Token created:", vpToken.substring(0, 100) + "...");

    // Create presentation submission
    const inputDescriptorIds = verification.presentationDefinition.input_descriptors.map(
      descriptor => descriptor.id
    );

    const cred = selectedCredential;
    const presentedFormat = cred.includes('~') ? 'dc+sd-jwt' : 'jwt_vc';
    const descriptorMap = inputDescriptorIds.map(id => ({
      id,
      format: presentedFormat,
      path: '$.vp.verifiableCredential[0]'
    }));

    T.t_vp_build = now();
    console.log(`[timing][wallet][${trace}] vp_build`);


    const form = new URLSearchParams();
    form.set('vp_token', vpToken);
    form.set('state', state);
    form.set('presentation_submission', JSON.stringify({
      id: crypto.randomBytes(8).toString('hex'),
      definition_id: verification.presentationDefinition.id,
      descriptor_map: descriptorMap
    }));


    T.t_present_req = now();
    console.log(`[timing][wallet][${trace}] present_req`);


    // Submit to verifier
    const submissionResponse = await axios.post(
      verification.redirectUri,
      form.toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'X-Trace': trace
        }
      }
    );

    T.t_present_res = now();
    console.log(`[timing][wallet][${trace}] present_res dur=${T.t_present_res - T.t_present_req}ms`);
    console.log(`[timing][wallet][${trace}] end total=${T.t_present_res - T.t_offer_recv}ms`);
    // ---- TIMING END (Wallet) ----


    pendingVerifications.delete(state);

    console.log("Verifier response status:", submissionResponse.status);
    console.log("Verifier response data:", submissionResponse.data);

    if (submissionResponse.data.redirect_url) {
      res.json({
        status: 'redirect',
        redirect_url: submissionResponse.data.redirect_url,
        verifier_response: submissionResponse.data
      });
    }
    else if (submissionResponse.data.error) {
      return res.status(400).json({
        error: 'verification_failed',
        message: submissionResponse.data.message || submissionResponse.data.error
      });
    } else {
      res.json({
        status: 'submitted',
        verifier_response: submissionResponse.data
      });
    }
  } catch (error) {
    console.error('Presentation submission failed:', error);
    if (error.response) {
      console.error('Verifier response:', error.response.data);
      return res.status(error.response.status).json({
        error: 'verification_failed',
        message: error.response.data.message || error.response.data.error
      });
    }
    res.status(400).json({
      error: 'submission_failed',
      message: error.message
    });
  }
});

/**
 * GET /health
 *
 * Liveness probe for K8s/monitoring. Always returns 200 { status: 'ok' }.
 */
// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});


// Start server
app.listen(port, () => {
  console.log(`Wallet backend running in SEV environment on port ${port}`);
  console.log(`Use /login to start a session`);
  console.log(`Use /process-offer with credential_offer_uri to issue credentials`);
});

