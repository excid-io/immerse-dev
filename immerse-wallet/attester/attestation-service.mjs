// attestation-service.mjs
import express from "express";
import axios from "axios";
import fs from "fs";
import crypto from "crypto";
import { execFileSync } from "child_process";

const app = express();
app.use(express.json());

const ALLOWED_SUBJECTS = (process.env.ALLOWED_SUBJECTS || "").split(",").filter(Boolean);
const ALLOWED_PAIRS = (process.env.ALLOWED_SERVICE_ACCOUNTS_PAIRS || "").split(",").filter(Boolean);

const ALLOWED_NAMESPACES = (process.env.ALLOWED_NAMESPACES || "cvm-wallets").split(",").filter(Boolean);
const ALLOWED_SERVICEACCOUNTS = (process.env.ALLOWED_SERVICEACCOUNTS || "wallet-sa").split(",").filter(Boolean);

//const ALLOWED_NAMESPACES = (process.env.ALLOWED_NAMESPACES || "cvm-wallets").split(",");
//const ALLOWED_SERVICEACCOUNTS = (process.env.ALLOWED_SERVICEACCOUNTS || "wallet-sa").split(",");
const SOFTHSM2_CONF = process.env.SOFTHSM2_CONF || "/etc/softhsm2/softhsm2.conf";
const PKCS11_MODULE = process.env.PKCS11_MODULE || "/usr/lib/softhsm/libsofthsm2.so";
const PKCS11_URI = process.env.PKCS11_URI || ""; // e.g., pkcs11:token=IMMERSE;object=AKEY;type=private
const PKCS11_PIN = process.env.PKCS11_PIN || "";
const AKEY_PEM_PATH = process.env.AKEY_PEM_PATH || ""; // fallback only

// ---------------- helpers ----------------
async function tokenReview(k8sToken) {
  const inClusterToken = fs.readFileSync("/var/run/secrets/kubernetes.io/serviceaccount/token", "utf8");
  const ca = fs.readFileSync("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
  const k8s = axios.create({
    baseURL: "https://kubernetes.default.svc",
    httpsAgent: new (await import("https")).Agent({ ca }),
    headers: { Authorization: `Bearer ${inClusterToken}` }
  });
  const resp = await k8s.post("/apis/authentication.k8s.io/v1/tokenreviews", {
    apiVersion: "authentication.k8s.io/v1",
    kind: "TokenReview",
    spec: { token: k8sToken }
  });
  return resp.data?.status;
}

function validateIdentity(status) {
  if (!status?.authenticated) return null;
  const subject = status.user?.username || ""; // e.g., system:serviceaccount:cvm-wallets:wallet-sa
  const parts = subject.split(":");
  //const ns = parts[3], sa = parts[4];
  const ns = parts[2], sa = parts[3];

  // 1) full-subject allowlist
  if (ALLOWED_SUBJECTS.length && ALLOWED_SUBJECTS.includes(subject)) {
    return { namespace: ns, serviceAccount: sa };
  }

  // 2) ns:sa pair allowlist
  if (ALLOWED_PAIRS.length && ALLOWED_PAIRS.includes(`${ns}:${sa}`)) {
    return { namespace: ns, serviceAccount: sa };
  }

  // 3) legacy split lists
  if (ALLOWED_NAMESPACES.includes(ns) && ALLOWED_SERVICEACCOUNTS.includes(sa)) {
    return { namespace: ns, serviceAccount: sa };
  }

  return null;
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

// ASN.1 DER (ECDSA) -> JOSE raw(R||S) for ES256
function derToJose(derSig) {
  // very small DER decoder for ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
  let b = Buffer.from(derSig);
  if (b[0] !== 0x30) throw new Error("Bad DER");
  let idx = 2; // skip seq tag+len (assume short form)
  if (b[1] & 0x80) idx = 2 + (b[1] & 0x7f); 
  if (b[idx] !== 0x02) throw new Error("Bad DER(r)");
  let rlen = b[idx+1]; let r = b.slice(idx+2, idx+2+rlen); idx += 2+rlen;
  if (b[idx] !== 0x02) throw new Error("Bad DER(s)");
  let slen = b[idx+1]; let s = b.slice(idx+2, idx+2+slen);
  // strip leading zeros then left-pad to 32
  const pad = x => (x[0] === 0x00 ? x.slice(1) : x);
  r = pad(r); s = pad(s);
  if (r.length > 32 || s.length > 32) throw new Error("Component too long");
  r = Buffer.concat([Buffer.alloc(32 - r.length, 0), r]);
  s = Buffer.concat([Buffer.alloc(32 - s.length, 0), s]);
  return Buffer.concat([r, s]);
}

function signWithPkcs11(signingInput) {
  const tmp = `/tmp/jws-${crypto.randomBytes(6).toString("hex")}.bin`;
  fs.writeFileSync(tmp, signingInput);
  try {
    const uriWithPin =
     PKCS11_PIN
       ? `${PKCS11_URI}${PKCS11_URI.includes("?") ? "&" : "?"}pin-value=${encodeURIComponent(PKCS11_PIN)}`
       : PKCS11_URI;
    // OpenSSL 1.1 engine syntax:
    const sigDer = execFileSync("openssl", [
      "dgst","-sha256",
      "-engine","pkcs11","-keyform","engine",
      //"-sign", PKCS11_URI,
      "-sign", uriWithPin,
      tmp
    //], { env: { ...process.env, SOFTHSM2_CONF } });
    ], {
      env: {
        ...process.env,
        SOFTHSM2_CONF,                     // where SoftHSM tokens live
        PKCS11_MODULE_PATH: PKCS11_MODULE  // engine_pkcs11 uses this var
      }
    });
    return Buffer.from(sigDer);
  } finally {
    fs.unlinkSync(tmp);
  }
}

function signWithPem(signingInput) {
  const sign = crypto.createSign("SHA256");
  sign.update(signingInput);
  sign.end();
  const keyPem = fs.readFileSync(AKEY_PEM_PATH, "utf8");
  // returns DER ECDSA signature
  return sign.sign(keyPem);
}

// ---------------- route ----------------
app.post("/attest", async (req, res) => {

  const trace = req.headers['x-trace'] || `tr_${Math.random().toString(16).slice(2,8)}`;
  const nowMs = () => Date.now();               // <-- rename
  const T = { t_attester_recv: nowMs() };
  console.log(`[timing][attester][${trace}] recv`);

  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "missing_bearer_token" });

    T.t_tokenreview_start = nowMs();
    const tr = await tokenReview(token);
    T.t_tokenreview_end = nowMs();
    console.log(`[timing][attester][${trace}] tokenreview dur=${T.t_tokenreview_end - T.t_tokenreview_start}ms`);

    const id = validateIdentity(tr);
    if (!id) return res.status(403).json({ error: "unauthorized_pod" });

    const { client_id, aud, ci_jwk, iat, exp } = req.body || {};
    if (!client_id || !aud || !ci_jwk) return res.status(400).json({ error: "invalid_request" });

    /*const now = Math.floor(Date.now()/1000);
    const payload = {
      iss: `urn:attester:${id.namespace}:${id.serviceAccount}`,
      sub: client_id,
      aud,
      iat: iat || now,
      exp: exp || (now + 3600),
      cnf: { jwk: ci_jwk }
    };*/
    const nowSec = Math.floor(Date.now() / 1000);   // <-- use nowSec, not now - time everything update
    const payload = {
      iss: `urn:attester:${id.namespace}:${id.serviceAccount}`,
      sub: client_id,
      aud,
      iat: iat || nowSec,
      exp: exp || (nowSec + 3600),
      cnf: { jwk: ci_jwk }
    };


    const header = { typ: "oauth-client-attestation+jwt", alg: "ES256" };
    const encodedHeader = b64url(JSON.stringify(header));
    const encodedPayload = b64url(JSON.stringify(payload));
    const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`);

    T.t_sign_start = nowMs();

    let sigDer;
    if (PKCS11_URI && PKCS11_PIN) {
      // OpenSSL engine uses PIN via env: set in container (pkcs11-tool usually uses env or config)
      process.env.PKCS11_MODULE_PATH = PKCS11_MODULE;
      process.env.PKCS11_PIN = PKCS11_PIN;
      sigDer = signWithPkcs11(signingInput);
    } else if (AKEY_PEM_PATH) {
      sigDer = signWithPem(signingInput);
    } else {
      return res.status(500).json({ error: "no_signer_available" });
    }

    T.t_sign_end = nowMs();
    console.log(`[timing][attester][${trace}] sign dur=${T.t_sign_end - T.t_sign_start}ms`);

    console.log(`[timing][attester][${trace}] end total=${nowMs() - T.t_attester_recv}ms`);

    const sigJose = derToJose(sigDer);
    const attestation = `${encodedHeader}.${encodedPayload}.${b64url(sigJose)}`;

    return res.json({ attestation });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error", message: String(e.message || e) });
  }
});

app.listen(5000, () => console.log("Attestation Service listening on :5000"));
