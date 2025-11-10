/**
 * IMMERSE VC Issuer (OID4VCI) - Implementation Notes
 *
 * Specs & drafts actually implemented in IMMERSE Issuer code:
 * - OpenID for Verifiable Credential Issuance (OID4VCI) 1.0 (OpenID spec)
 *   Issuer metadata (Well-Known), pre-authorized code token flow,
 *   c_nonce issuance, Credential Endpoint with proof type "jwt"
 * - SD-JWT-based Verifiable Credentials (SD-JWT VC) draft
 *   dc+sd-jwt media type, disclosures & digests, holder binding via cnf.jwk,
 *   standard iat/exp/jti claims
 * - OAuth 2.0 (core flow elements for token exchange with pre-authorized code)
 * - OAuth Attestation-Based Client Authentication (ABCA) draft
 *   Verifies Client PoP at /token, parses Client-Attestation structurally
 *   and checks cnf.jwk binding.
 * - JOSE / JWT relevant specs:
 *   RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK thumbprint)
 * 
 * Referenced for terminology/structural alignment (non-normative here):
 * - W3C Verifiable Credentials Data Model 2.0 (VCDM 2.0)
 *   Used for naming/semantics of credentialSubject fields and general vocabulary.
 *   This issuer's signing profile is SD-JWT VC, not W3C JWT-VC.
 *
 * Additional information about this code:
 * - Anti-replay at /token via jti cache, short-lived PoP with aud=/token
 * - SD-JWT VC holder binding (cnf.jwk) and 1-year exp default
 * - Revocation/status list exposure (issuer publishes a simple list endpoint)
 *
 * Deployment notes (demo):
 * - Issuer exposes its own JWKS at /.well-known/jwks.json. This endpoint SHOULD 
 *   be treated as the source of truth.
 * - Optional "key registry" is a convenience directory for discovery in the demo,
 *   it is not the issuer's JWKS per OID4VCI and does not enforce any security checks.
 */

// Required libraries: Express (HTTP), jose (JWS/JWK), crypto (keys), base64url, axios (HTTP client)
import express from 'express';
import { SignJWT, jwtVerify, calculateJwkThumbprint, importJWK } from 'jose';
import crypto from 'crypto';
import base64url from 'base64url';
import axios from 'axios';

const app = express();
const port = process.env.PORT || 8000;

// Configuration with env variables and key management
// - ISSUER_BASE_URL: must match the OID4VCI "credential_issuer" value in well-known metadata.
const ISSUER_BASE_URL = process.env.ISSUER_BASE_URL || `http://localhost:${port}`;
const WALLET_FRONTEND_URL = process.env.WALLET_FRONTEND_URL || "ADD HERE YOUR HTTP FR URL AND PORT"; 
// - KEY_REGISTRY_URL: demo-only helper for discovery - IMMERSE issuer still serves its own JWKS.
const KEY_REGISTRY_URL = process.env.KEY_REGISTRY_URL || 'http://key-registry:8080';
const POD_NAME = process.env.POD_NAME || 'default-pod';
let keyPair;
let currentKid;


/**
 * Generate P-256 EC key pair for signing credentials
 * 
 * Cryptographic Standards:
 * RFC 7518 - ES256 (ECDSA over P-256). Node crypto generates an EC keypair.
 * We later export the public part as JWK for JWKS and the private for signing.
 */
function generateKeyPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  });
}

/**
 * Register Public Key with Key Registry (non-OID4VCI requirement)
 * 
 * We POST the issuer's public JWK (+ a KID) to a central registry used in our demo.
 * Verifiers SHOULD prefer the issuer's own JWKS at /.well-known/jwks.json.
 */
async function registerKey() {
  try {
    const publicJwk = keyPair.publicKey.export({ format: 'jwk' });
    currentKid = `issuer-${POD_NAME}-${Date.now()}`;
    
    await axios.post(`${KEY_REGISTRY_URL}/register`, {
      kid: currentKid,
      publicKey: publicJwk,
      issuer: ISSUER_BASE_URL
    });
    
    console.log(`Registered new key: ${currentKid}`);
  } catch (err) {
    console.error('Failed to register key:', err.message);
    process.exit(1);
  }
}


// Session and offer management with automatic cleanup: in-memory store for demo - production would use storage.
const sessions = new Map();
const credentialOffers = new Map();

// K8s health endpoints (readiness/liveness).
app.get('/healthz', (req, res) => res.status(200).send('OK'));
app.get('/readyz', (req, res) => keyPair ? res.status(200).send('OK') : res.status(503).send('Initializing'));

// Body parsing:
// - application/x-www-form-urlencoded for /token (OID4VCI)
// - application/json for /credential (OID4VCI)
app.use(express.urlencoded({ extended: false })); 
app.use(express.json()); 

/* Metadata endpoint - OID4VCI Section 12: Issuer Metadata Endpoint
 *
 * SD-JWT VC from Verifiable Credentials Data Model v2.0, SD-JWT-based 
 * Verifiable Credentials (SD-JWT VC) [draft-ietf-oauth-sd-jwt-vc-12]
 * "Note that this draft used vc+sd-jwt as the value of the typ header
 * from its inception in July 2023 until November 2024 when it was
 * changed to dc+sd-jwt to avoid conflict with the vc media type name
 * registered by the W3C's Verifiable Credentials Data Model draft.  In
 * order to facilitate a minimally disruptive transition, it is
 * RECOMMENDED that Verifiers and Holders accept both vc+sd-jwt and
 * dc+sd-jwt as the value of the typ header for a reasonable
 * transitional period." [sec.3.2.1, draft-ietf-oauth-sd-jwt-vc-12]
 * Furthermore, "SD-JWT VCs compliant with this specification MUST use 
 * the media type application/dc+sd-jwt." and "The base subtype name dc 
 * is meant to stand for "digital credential", which is a term that is 
 * emerging as a conceptual synonym for "verifiable credential.", from
 * [sec.3.1, draft-ietf-oauth-sd-jwt-vc-12]
 */
app.get('/.well-known/openid-credential-issuer', (req, res) => {
  // "unsigned JSON document using the media type application/json", 
  // "MUST support returning metadata in an unsigned form 'application/json' and MAY 
  // support returning it in a signed form 'application/jwt'", OID4VCI, sec.12.2.2
  res.json({
    credential_issuer: ISSUER_BASE_URL, // REQUIRED, OI4VCI sec.12.2.4
    token_endpoint: `${ISSUER_BASE_URL}/token`,
    credential_endpoint: `${ISSUER_BASE_URL}/credential`, // REQUIRED, OI4VCI sec.12.2.4
    credential_configurations_supported: [  // REQUIRED, OI4VCI sec.12.2.4
      {
        format: 'dc+sd-jwt', //  REQUIRED
        vct: 'UniversityDegreeCredential',  //REQUIRED. OI4VCI sec.A.3.2
        cryptographic_binding_methods_supported: ['jwk'], // OPTIONAL
        credential_signing_alg_values_supported: ['ES256'], // OPTIONAL
        //proof_types_supported: ['jwt'] // OPTIONAL
        proof_types_supported: { // OPTIONAL
          "jwt": {
            proof_signing_alg_values_supported: ["ES256"] // REQUIRED
          }
        }
      },
      {
        // optional legacy 
        // note that this implementation will only support dc+sd-jwt however the IMMERSE wallet & Verifier will be able to accept both
        format: 'vc+sd-jwt',
        vct: 'UniversityDegreeCredential',
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: { // OPTIONAL
          "jwt": {
            proof_signing_alg_values_supported: ["ES256"] // REQUIRED
          }
        }
      }
    ]
  });
});

// REVOCATION UPDATES

/**
 * Credential Revocation System
 * 
 * Implements:
 * - Verifier checks JTI against an issuer-hosted JSON list.
 * - Simple status list for revocation tracking
 * - Administrative controls for credential management
 */
const revokedJtis = new Set();

// Admin endpoint to revoke a VC manually, see revoc-exp doc in docs
app.post('/admin/revoke', express.json(), (req, res) => {
  const { jti } = req.body || {};
  if (!jti) return res.status(400).json({ error: 'missing_jti' });
  revokedJtis.add(jti);
  console.log(`Revoked credential JTI: ${jti}`);
  res.json({ revoked: jti, total_revoked: revokedJtis.size });
});

// Public revocation list endpoint (used by verifiers)
app.get('/.well-known/credential-status.json', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    issuer: ISSUER_BASE_URL,
    updated_at: new Date().toISOString(),
    type: 'StatusList2025',
    statusPurpose: 'revocation',
    revoked: Array.from(revokedJtis)
  });
});

// REVOCATION UPDATES 

// ===== CREDENTIAL ISSUANCE FLOW =====

app.get('/', (req, res) => {
  res.redirect(302, '/authorize'); 
});

/**
 * OID4VCI Section 5: Authorization Endpoint
 * 
 * Initiates the credential issuance flow with:
 * - Session state management for security
 * - CSRF protection through state parameter
 * - Redirect-based user interaction
 */
app.get('/authorize', (req, res) => {
  const sessionId = crypto.randomBytes(16).toString('hex');
  const state = crypto.randomBytes(16).toString('hex');
  sessions.set(sessionId, { state, createdAt: Date.now() });
  res.redirect(`/callback?code=${sessionId}&state=${state}`);
});

/**
 * OID4VCI Section 6: Credential Offer Endpoint
 * 
 * Delivers credential offer to wallet through:
 * - Pre-authorized code grant
 * - OpenID Credential Offer URI syntax
 * - Deep linking to wallet applications
 */
app.get('/callback', (req, res) => {
  const { code, state } = req.query;
  const session = sessions.get(code);

  if (!session || session.state !== state) {
    return res.status(400).send('Invalid session');
  }

  // pre-authorized_code: The code representing the authorization to obtain Credentials of a certain type. 
  // This parameter MUST be present if the grant_type is urn:ietf:params:oauth:grant-type:pre-authorized_code.
  // sec.6.1,sec3.5 OID4VCI

  const preAuthorizedCode = `preauth_${crypto.randomBytes(32).toString('hex')}`;
  const credentialOffer = {
    credential_issuer: ISSUER_BASE_URL,
    credentials: [{
      format: "dc+sd-jwt", //format: "jwt_vc", was before sd jwt changes. 
      // Note we only keep the new format for actual issuance.
      //types: ["VerifiableCredential", "UniversityDegreeCredential"]
      vct: "UniversityDegreeCredential"
    }],
    grants: {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": preAuthorizedCode,
        "user_pin_required": false
      }
    }
  };

  credentialOffers.set(preAuthorizedCode, {
    sessionId: code,
    status: 'pending',
    createdAt: Date.now()
  });

  //const encodedOffer = base64url.encode(JSON.stringify(credentialOffer));
  // Create deep link instead of QR code
  //const walletDeepLink = `${WALLET_FRONTEND_URL}/?credential_offer=${encodedOffer}`;
  const encodedOffer = base64url.encode(JSON.stringify(credentialOffer));
  const openidOffer = `openid-credential-offer://?credential_offer=${encodedOffer}`;
  const walletDeepLink = `${WALLET_FRONTEND_URL}/?credential_offer=${encodeURIComponent(openidOffer)}`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Immersive Credential Issuer</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <style>
        :root {
            --primary: #4361ee;
            --secondary: #3a0ca3;
            --accent: #f72585;
            --light: #f8f9fa;
            --dark: #212529;
            --success: #4cc9f0;
            --warning: #f9c74f;
            --danger: #f94144;
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: var(--light);
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            margin-bottom: 30px;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            display: flex;
            align-items: center;
        }

        .logo-icon {
            margin-right: 10px;
            font-size: 28px;
            color: var(--success);
        }

        nav ul {
            display: flex;
            list-style: none;
        }

        nav li {
            margin-left: 20px;
        }

        nav a {
            color: var(--light);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
            padding: 8px 16px;
            border-radius: 20px;
            display: flex;
            align-items: center;
        }

        nav a i {
            margin-right: 8px;
        }

        nav a:hover, nav a.active {
            background: rgba(255, 255, 255, 0.1);
        }

        .mode-selector {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 10px;
        }

        .mode-btn {
            padding: 12px 24px;
            margin: 0 10px;
            border: none;
            background: transparent;
            color: var(--light);
            cursor: pointer;
            border-radius: 8px;
            font-weight: 500;
            transition: var(--transition);
            display: flex;
            align-items: center;
        }

        .mode-btn i {
            margin-right: 8px;
        }

        .mode-btn.active {
            background: var(--primary);
            box-shadow: 0 4px 15px rgba(67, 97, 238, 0.3);
        }

        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        h1, h2, h3 {
            margin-bottom: 15px;
            font-weight: 600;
        }

        h1 {
            font-size: 2.5rem;
            background: linear-gradient(to right, #4cc9f0, #4361ee);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        p {
            line-height: 1.6;
            margin-bottom: 15px;
            color: rgba(255, 255, 255, 0.8);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            padding: 12px 28px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
            box-shadow: 0 4px 15px rgba(67, 97, 238, 0.3);
        }

        .btn i {
            margin-right: 8px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(67, 97, 238, 0.4);
        }

        .btn-secondary {
            background: transparent;
            border: 1px solid var(--primary);
            color: var(--primary);
        }

        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }

        .feature {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: var(--transition);
        }

        .feature:hover {
            transform: translateY(-5px);
            background: rgba(255, 255, 255, 0.1);
        }

        .feature-icon {
            font-size: 40px;
            margin-bottom: 15px;
            color: var(--success);
        }

        /* Canvas for 3D/AR */
        #canvas-container {
            width: 100%;
            height: 500px;
            position: relative;
            border-radius: 12px;
            overflow: hidden;
            margin: 30px 0;
        }

        #preview-canvas, #ar-canvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        .simulation-controls {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-top: 20px;
        }

        .control-btn {
            display: flex;
            align-items: center;
            padding: 10px 20px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: white;
            border-radius: 8px;
            cursor: pointer;
            transition: var(--transition);
        }

        .control-btn i {
            margin-right: 8px;
        }

        .control-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .instruction-box {
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(0, 0, 0, 0.7);
            padding: 15px;
            border-radius: 8px;
            max-width: 400px;
            font-size: 14px;
            line-height: 1.5;
        }

        .typing-cursor {
            display: inline-block;
            width: 2px;
            height: 1em;
            background: white;
            margin-left: 2px;
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }

        footer {
            text-align: center;
            padding: 30px 0;
            margin-top: 50px;
            color: rgba(255, 255, 255, 0.6);
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            header {
                flex-direction: column;
                text-align: center;
            }
            
            nav ul {
                margin-top: 15px;
                justify-content: center;
            }
            
            nav li {
                margin: 0 10px;
            }
            
            .mode-selector {
                flex-direction: column;
                gap: 10px;
            }
            
            #canvas-container {
                height: 350px;
            }
            
            h1 {
                font-size: 2rem;
            }
        }

        /* 2D UI specific */
        .ui-2d {
            display: block;
        }

        /* 3D Preview specific */
        .ui-preview {
            display: none;
        }

        /* AR specific */
        .ui-ar {
            display: none;
        }
        
        /* Draft CSS override of styles -- will REMOVE duplicates later */
        /* ===== Mobile tweaks (safe for desktop) ===== */
	@media (max-width: 640px) {
	  /* start fix for mobile */
	  .simulation-controls {
	    flex-wrap: wrap;
	    gap: 10px 10px;
	    justify-content: center;
	    padding: 8px 12px;
	  }
	  .simulation-controls .control-btn {
	    flex: 1 1 calc(50% - 10px);   /* two per row */
	    min-width: 140px;             /* avoid tiny chips */
	    justify-content: center;
	  }
	  /* keep hint box from overflowing on small screens */
	  .instruction-box { max-width: min(90vw, 420px); }
	  /* end fix for mobile */
  
	  .container { padding: 12px; }

	  /* Stack brand and nav, keep things compact */
	  header {
	    flex-direction: column;
	    align-items: center;
	    gap: 8px;
	  }

	  .logo {
	    font-size: clamp(18px, 6vw, 22px);
	    line-height: 1.15;
	  }
	  .logo span {
	    /* allow the long title to break nicely on small screens */
	    word-break: break-word;
	    text-wrap: balance;          /* fine if unsupported - it just no-ops */
	  }

	  /* Make the nav wrap instead of overflowing off-screen */
	  nav ul {
	    flex-wrap: wrap;
	    justify-content: center;
	    gap: 8px 10px;
	    margin-top: 6px;             /* smaller than desktop */
	  }
	  nav li { margin: 0; }
	  nav a {
	    padding: 8px 12px;
	    font-size: 14px;
	    border-radius: 14px;
	  }
	  nav a i { margin-right: 6px; font-size: 14px; }

	  /* Mode selector: full-width buttons on mobile */
	  .mode-selector {
	    flex-direction: column;
	    gap: 8px;
	    padding: 8px;
	  }
	  .mode-btn {
	    width: 100%;
	    margin: 0;
	    justify-content: center;
	  }

	  /* Cards/canvas a bit tighter so content fits above the fold */
	  .card { padding: 18px; }
	  #canvas-container { height: min(55vh, 360px); }

	  /* Avoid iOS zoom-on-focus & keep inputs readable -iphone tests */
	  input, textarea { font-size: 16px; }
	}
	/* END overrides */
	
	/* REMOVE */
	/* Credential panel in 3D preview */
	.offer-panel {
	  position: absolute;
	  right: 20px;
	  bottom: 20px;
	  width: 320px;
	  background: rgba(0,0,0,0.72);
	  border: 1px solid rgba(255,255,255,0.12);
	  border-radius: 12px;
	  padding: 16px 18px;
	  box-shadow: 0 8px 24px rgba(0,0,0,0.35);
	  display: none;
	  backdrop-filter: blur(8px);
	}
	.offer-panel.show { display: block; }
	.offer-panel h2 {
	  margin: 0 0 8px;
	  font-size: 18px;
	  font-weight: 600;
	}
	.offer-panel .muted { color: rgba(255,255,255,0.75); }
	.offer-panel .actions {
	  display: flex;
	  gap: 10px;
	  flex-wrap: wrap;
	  margin-top: 12px;
	}
	.offer-panel .panel-close {
	  position: absolute;
	  top: 6px; right: 8px;
	  background: transparent;
	  border: 0;
	  color: rgba(255,255,255,0.7);
	  font-size: 20px;
	  cursor: pointer;
	}
	@media (max-width: 640px) {
	  .offer-panel { left: 10px; right: 10px; width: auto; }
	}
	/* REMOVE */
	:root { --ar-controls-h: 84px; }
	.instruction-box { z-index: 2; }
	.offer-panel     { z-index: 3; }  
	/* AR 3D SCENE UPDATES*/
	/* Make AR view sharp & unobstructed (no card blur/chrome) */
	body.ar-active .ui-ar.card {
	  background: transparent;
	  border: 0;
	  backdrop-filter: none;
	  box-shadow: none;
	  padding: 0;
	}

	
	
	/* Reserve space for the bottom controls so content/hints never sits on them */
	body.ar-active #ar-container {
	  /* use 100svh for better mobile viewport-- browsers that lack it will just use it as 100vh */
	  height: calc(100svh - var(--ar-controls-h));
	  margin: 0;
	  border-radius: 0;
	}
	
	/* Keep the hint readable and out of the button bar */
	body.ar-active #ar-container .instruction-box {
	  bottom: 16px;                 /* the container is shorter by the controls height */
	  pointer-events: none;
	  z-index: 10;
	  background: rgba(0,0,0,0.40);
	}
	

	
	/* Make sure the bottom button row is above the hint */
	body.ar-active .ui-ar .simulation-controls {
	  position: relative;
	  z-index: 20;
	  margin-top: 0;
	  padding-top: 12px;
	  background: transparent;
	}
	
	/* Avoid browser pinch-zoom/two-finger pan fighting withx gestures */
	#ar-canvas { touch-action: none; }
	
	#ar-container {
	  position: relative;   /* make absolute-positioned .instruction-box anchor here */
	}

    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-graduation-cap logo-icon"></i>
                <span>University Credential Issuer</span>
            </div>
            <nav>
                <ul>
                    <li><a href="#" class="active" id="home-link"><i class="fas fa-home"></i> Home</a></li>
                    <li><a href="#credentials"><i class="fas fa-certificate"></i> Credentials</a></li>
                    <li><a href="#about"><i class="fas fa-info-circle"></i> About</a></li>
                    <li><a href="#contact"><i class="fas fa-envelope"></i> Contact</a></li>
                </ul>
            </nav>
        </header>

        <div class="mode-selector">
            <button class="mode-btn active" data-mode="2d"><i class="fas fa-desktop"></i> 2D Preview</button>
            <button class="mode-btn" data-mode="preview"><i class="fas fa-vr-cardboard"></i> 3D Preview</button>
            <button class="mode-btn" data-mode="ar"><i class="fas fa-glasses"></i> AR Experience</button>
        </div>

        <!-- 2D Desktop UI -->
        <section class="ui-2d card">
            <h1>Get Your Verifiable Credential</h1>
            <p>The University Credential Issuer issues a digital credential that you can store in your wallet and share with anyone you choose. Your credential is cryptographically signed and can be verified instantly.</p>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-lock"></i></div>
                    <h3>Secure</h3>
                    <p>Your credentials are cryptographically signed and tamper-proof.</p>
                </div>
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-mobile-alt"></i></div>
                    <h3>Portable</h3>
                    <p>Store your credentials in any compatible wallet and take them anywhere.</p>
                </div>
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-globe"></i></div>
                    <h3>Interoperable</h3>
                    <!--p>Works across different platforms and systems using open standards.</p-->
                    <p>Built using reliable and open standards.</p>
                </div>
            </div>
            
            <!-- a href="/authorize" class="btn"><i class="fas fa-play-circle"></i> Get Started</a -->
            <a id="btn-2d-get-credential" href="${walletDeepLink}" class="btn"><i class="fas fa-wallet"></i> Get Credential</a>
            <a href="https://github.com/excid-io/immerse-dev" class="btn btn-secondary"><i class="fas fa-book"></i> Learn More</a>
            
            <!-- check tip to make sure it matches verifier-->
            <p style="margin-top: 20px; color: rgba(255, 255, 255, 0.7); font-size: 14px;">
                <i class="fas fa-lightbulb"></i> Tip: On a phone or headset with WebXR, the AR mode lets you select a floating orb to open your wallet.
            </p>
        </section>

        <!-- 3D Preview UI -->
        <section class="ui-preview card">
            <h1>3D Preview Experience</h1>
            <!--p>Experience what the AR credential issuance would look like. In this simulation, you can interact with 3D objects and see how the process would work in augmented reality.</p-->
            <p>Explore how credential issuance works in augmented reality through an interactive 3D experience-no headset required.</p>
            <div id="canvas-container">
                <canvas id="preview-canvas"></canvas>
                <div class="instruction-box" id="instruction-box"></div>
                    <!-- Instructions will be typed here -->
                    
                <!-- Credential offer overlay -- REMOVE -->
                <div class="offer-panel" id="offer-panel">
		    <button class="panel-close" id="offer-close" aria-label="Close">&times;</button>
		    <h2><i class="fas fa-certificate"></i> Credential Offer Ready</h2>
		    <p class="muted">Click the glowing orb, or use the button below to add the credential to your wallet.</p>
		    <div class="actions">
		      <a class="btn" id="offer-add">Add to Wallet</a>
		      <button class="btn btn-secondary" id="offer-copy">Copy Link</button>
		    </div>
		</div>
		<!-- END Credential offer overlay -- REMOVE -->
                
            </div>
            
            <div class="simulation-controls">
                <button class="control-btn" id="sound-toggle"><i class="fas fa-volume-mute"></i> Sound Off</button>
                <button class="control-btn" id="replay-instructions"><i class="fas fa-redo"></i> Replay Instructions</button>
                <button class="control-btn" id="enter-ar"><i class="fas fa-glasses"></i> Enter AR</button>
                
                <button class="control-btn" id="open-offer"><i class="fas fa-wallet"></i> Get Credential</button>
            </div>
        </section>

        <!-- AR Experience UI -->
        <section class="ui-ar card">
            <h1>AR Credential Experience</h1>
            <p>Put on your AR headset to experience credential issuance in augmented reality. Follow the instructions to receive your verifiable credential.</p>
            
            <!--div id="canvas-container"-->
            <div id="ar-container">
                <canvas id="ar-canvas"></canvas>
                <div class="instruction-box" id="ar-instruction-box">
                    <!-- AR instructions will be typed here -->
                </div>
            </div>
            
            <div class="simulation-controls">
                <button class="control-btn" id="ar-sound-toggle"><i class="fas fa-volume-mute"></i> Sound Off</button>
                <!-- ar fixed -->
                <button class="control-btn" id="ar-get-credential"><i class="fas fa-wallet"></i> Get Credential</button>
    		<button class="control-btn" id="ar-replay-instructions"><i class="fas fa-redo"></i> Replay Instructions</button>
                <button class="control-btn" id="exit-ar"><i class="fas fa-times"></i> Exit AR</button>
            </div>
        </section>

        <!-- Credentials Section -->
        <section id="credentials" class="card">
            <h2><i class="fas fa-certificate"></i> Available Credentials</h2>
            <!--p>Our issuer supports the following credential types:</p-->
            <p>Our issuer issues credentials that include the following attributes:</p>
            <!--ul>
                <li><i class="fas fa-graduation-cap"></i> University Degree Credentials</li>
                <li><i class="fas fa-award"></i> Professional Certifications</li>
                <li><i class="fas fa-medal"></i> Workshop Completion Badges</li>
                <li><i class="fas fa-star"></i> Skills Verification Credentials</li>
            </ul-->
            <ul>
                <li><i class="fas fa-graduation-cap"></i> Student Profile</li>
                <li><i class="fas fa-award"></i> Course Participation</li>
                <li><i class="fas fa-medal"></i> Academic Record</li>
                <li><i class="fas fa-star"></i> Verified Enrollment Status</li>
            </ul>
        </section>

        <!-- About Section -->
        <section id="about" class="card">
            <h2><i class="fas fa-info-circle"></i> About Our Issuer</h2>
            <p>We provide a standards-based platform for issuing secure, verifiable credentials to enrolled students. Our platform leverages OpenID for Verifiable Credential Issuance (OID4VCI) to ensure interoperability and security.</p>
            <p>Our mission is to make credential issuance and verification seamless, secure, and accessible to everyone.</p>
        </section>

        <!-- Contact Section -->
        <section id="contact" class="card">
            <h2><i class="fas fa-envelope"></i> Contact Us</h2>
            <p>Have questions about our credential issuance platform? Get in touch with our team.</p>
            <form id="contact-form">
                <div style="margin-bottom: 15px;">
                    <label for="name" style="display: block; margin-bottom: 5px;"><i class="fas fa-user"></i> Name:</label>
                    <input type="text" id="name" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;">
                </div>
                <div style="margin-bottom: 15px;">
                    <label for="email" style="display: block; margin-bottom: 5px;"><i class="fas fa-envelope"></i> Email:</label>
                    <input type="email" id="email" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;">
                </div>
                <div style="margin-bottom: 15px;">
                    <label for="message" style="display: block; margin-bottom: 5px;"><i class="fas fa-comment"></i> Message:</label>
                    <textarea id="message" rows="4" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;"></textarea>
                </div>
                <button type="submit" class="btn"><i class="fas fa-paper-plane"></i> Send Message</button>
            </form>
        </section>

        <footer>
            <p>2025 University Credential Issuer | Powered by ExcID | Funded by SPIRIT</p>
        </footer>
    </div>
    <script>
        // REMOVE
        let previewInit = false;
	let raycaster, pointer, clickableOrb;

	function goToWallet() {
	  // Use direct navigation so deep links fire on mobile
	  window.location.href = "${walletDeepLink}";
	}

	function openOfferPanel() {
	  document.getElementById('offer-panel').classList.add('show');
	}

	function closeOfferPanel() {
	  document.getElementById('offer-panel').classList.remove('show');
	}
	// REMOVE
        
        const audio = { ctx: null, gain: null, enabled: false };
	function ensureAudioCtx() {
	    // create or resume on demand (must be called from a user gesture to unlock)
	    if (!audio.ctx) {
	      audio.ctx = new (window.AudioContext || window.webkitAudioContext)();
	      audio.gain = audio.ctx.createGain();
	      audio.gain.gain.value = 0.25; // master volume
	      audio.gain.connect(audio.ctx.destination);
	    }
	    if (audio.ctx.state === 'suspended') {
	      audio.ctx.resume();
	    }
	  }

	  function setSoundEnabled(on) {
	    audio.enabled = !!on;
	    if (audio.enabled) ensureAudioCtx();
	    updateSoundButtons();
	    window.addEventListener('pointerdown', function(){
	        if (audio.enabled) ensureAudioCtx();
	    }, { once: true });

	    window.addEventListener('keydown', function(){
	        if (audio.enabled) ensureAudioCtx();
	    }, { once: true });
	    if (audio.enabled) {
	    try {
	      var activeElId = null;
	      if (document.querySelector('.ui-preview') && document.querySelector('.ui-preview').style.display !== 'none') {
		activeElId = 'instruction-box';
	      } else if (document.querySelector('.ui-ar') && document.querySelector('.ui-ar').style.display !== 'none') {
		activeElId = 'ar-instruction-box';
	      }
	      var t = activeElId ? lastInstruction[activeElId] : null;
	      if (t) { if ('speechSynthesis' in window) window.speechSynthesis.cancel(); speak(t); }
	    } catch (_) {}
	    } else {
	      if ('speechSynthesis' in window) window.speechSynthesis.cancel();
	    }
	  }
	  

	  function sfx(kind) {
	    if (!audio.enabled) return;
	    ensureAudioCtx();

	    const now = audio.ctx.currentTime;
	    const o = audio.ctx.createOscillator();
	    const g = audio.ctx.createGain();
	    o.connect(g); g.connect(audio.gain);

	    if (kind === 'tick') {
	      o.type = 'square';
	      o.frequency.setValueAtTime(1200, now);
	      g.gain.setValueAtTime(0.08, now);
	      g.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
	      o.start(now); o.stop(now + 0.08);
	    } else { // 'chime' default
	      o.type = 'sine';
	      o.frequency.setValueAtTime(880, now);
	      o.frequency.exponentialRampToValueAtTime(440, now + 0.22);
	      g.gain.setValueAtTime(0.12, now);
	      g.gain.exponentialRampToValueAtTime(0.001, now + 0.24);
	      o.start(now); o.stop(now + 0.26);
	    }
	  }

	  function updateSoundButtons() {
	    ['sound-toggle','ar-sound-toggle'].forEach(function(id){
	      var btn = document.getElementById(id);
	      if (!btn) return;
	      var icon = btn.querySelector('i');
	      if (icon) icon.className = audio.enabled ? 'fas fa-volume-up' : 'fas fa-volume-mute';
	      btn.innerHTML = '<i class="' + (audio.enabled ? 'fas fa-volume-up' : 'fas fa-volume-mute') + '"></i> ' + (audio.enabled ? 'Sound On' : 'Sound Off');
	    });
	  }
	  
	  let selectedVoice = null;

	const VOICE_PREFERENCE = [
	  // Windows / Edge natural voices
	  'Microsoft Aria Online (Natural) - English (United States)',
	  'Microsoft Jenny Online (Natural) - English (United States)',
	  'Microsoft Guy Online (Natural)',
	  // Chrome voices
	  'Google US English',
	  'Google UK English Female',
	  'Google UK English Male',
	  // apple voices (?) - check at ui tests with iphone or mac if available
	  'Samantha', 'Ava', 'Alex', 'Victoria', 'Karen', 'Daniel'
	];
	const VOICE_LANGS = ['en-US','en-GB','en-AU','en-CA'];

	function pickVoice() {
	  const voices = window.speechSynthesis.getVoices();
	  if (!voices || !voices.length) return null;

	  // exact name match first
	  for (const name of VOICE_PREFERENCE) {
	    const v = voices.find(v => v.name === name);
	    if (v) return v;
	  }
	  // fallback: partial match by preference order
	  for (const hint of VOICE_PREFERENCE) {
	    const v = voices.find(v => v.name.toLowerCase().includes(hint.toLowerCase()));
	    if (v) return v;
	  }
	  // fallback: language family
	  const byLang = voices.find(v => VOICE_LANGS.includes((v.lang || '').trim()));
	  return byLang || voices[0];
	}

	function initVoiceOnce() {
	  if (!('speechSynthesis' in window) || selectedVoice) return;
	  const haveNow = window.speechSynthesis.getVoices();
	  if (haveNow && haveNow.length) {
	    selectedVoice = pickVoice();
	  } else {
	    // voices load async in some browsers
	    window.speechSynthesis.onvoiceschanged = () => {
	      if (!selectedVoice) selectedVoice = pickVoice();
	    };
	  }
	}
	initVoiceOnce();

	function speak(text) {
	  if (!audio.enabled) return;                     // sound toggle
	  if (!('speechSynthesis' in window)) return;

	  initVoiceOnce();
	  try {
	    window.speechSynthesis.cancel();              // stop any ongoing speech
	    const u = new SpeechSynthesisUtterance(text);
	    if (selectedVoice) u.voice = selectedVoice;   // use our chosen voice
	    u.rate = 0.95;                                // defaults
	    u.pitch = 1.0;
	    u.volume = 1.0;
	    window.speechSynthesis.speak(u);
	  } catch (e) {
	    console.warn('TTS error:', e);
	  }
	}
	  
	var typingState = {};           // elementId -> { token, timer }
	var lastInstruction = {};       // elementId -> last full text (for TTS replay)

	function clearTyping(elementId) {
	  var st = typingState[elementId];
	  if (st && st.timer) clearTimeout(st.timer);
	  typingState[elementId] = null;
	}

	

	// Safer typewriter-phase 6 ui- uses a textNode - keep
	function typeInstruction(text, elementId, speed) {
	  speed = (typeof speed === 'number' ? speed : 40);
	  var el = document.getElementById(elementId);
	  if (!el) return;

	  // remember latest text for this box (so we can speak it later on Sound On)
	  lastInstruction[elementId] = text;

	  // cancel previous typing for this element
	  clearTyping(elementId);

	  // cancel any current speech, then start new narration in parallel
	  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
	  speak(text);

	  // fresh run token
	  var token = Symbol('typing');
	  typingState[elementId] = { token: token, timer: null };

	  // text node avoids re-parsing HTML each char
	  el.innerHTML = '';
	  var tn = document.createTextNode('');
	  el.appendChild(tn);

	  var i = 0, tickEvery = 3;
	  function step() {
	    var st = typingState[elementId];
	    if (!st || st.token !== token) return; // aborted / superseded
	    if (i < text.length) {
	      tn.data += text.charAt(i);
	      if (audio.enabled && (i % tickEvery === 0)) sfx('tick');
	      i++;
	      st.timer = setTimeout(step, speed);
	    } else {
	      el.insertAdjacentHTML('beforeend', '<span class="typing-cursor"></span>');
	    }
	  }
	  step();
	}
	
        // Mode switching functionality
        function setMode(mode) {
	  // stop any narration when changing modes
	  if ('speechSynthesis' in window) window.speechSynthesis.cancel();

	  // update active button
	  document.querySelectorAll('.mode-btn').forEach(function(btn){
	    btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
	  });

	  // show/hide sections
	  document.querySelectorAll('[class^="ui-"]').forEach(function(sec){
	    sec.style.display = 'none';
	  });
	  var show = document.querySelector('.ui-' + mode);
	  if (show) show.style.display = 'block';

	  // init per mode
	  if (mode === 'preview')      initPreviewMode();
	  //else if (mode === 'ar')      initARMode();
	  // toggle AR chrome immediately (even if XR won't start to get CSS right)
	  
	  if (mode === 'ar') {
	    document.body.classList.add('ar-active');
	    setArControlsHeight();      // measure controls and set the CSS var
	    initARMode(true);               // start/prepare AR scene
	    // fallback
	    // if (navigator.xr && window.__startImmersiveAR) window.__startImmersiveAR();
    	    // return;
	  } else {
	    document.body.classList.remove('ar-active');
	  }
	}
	// fixing ar css
	function setArControlsHeight() {
	  const controls = document.querySelector('.ui-ar .simulation-controls');
	  if (!controls) return;
	  const h = controls.offsetHeight + 12; // little extra breathing room
	  document.documentElement.style.setProperty('--ar-controls-h', h + 'px');
	}
	
	// fixing ar css
	// if the layout changes
	window.addEventListener('resize', setArControlsHeight);
	if ('fonts' in document) document.fonts.ready.then(setArControlsHeight);
	document.addEventListener('DOMContentLoaded', setArControlsHeight);


	document.querySelectorAll('.mode-btn').forEach(function(button){
	  button.addEventListener('click', function(){
	    var m = button.getAttribute('data-mode');
	    sfx('chime');
	    setMode(m);
	  });
	});
        /*document.querySelectorAll('.mode-btn').forEach(button => {
            button.addEventListener('click', () => {
                const mode = button.getAttribute('data-mode');
                
                // Update active button
                document.querySelectorAll('.mode-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                button.classList.add('active');
                sfx('chime');
                if ('speechSynthesis' in window) window.speechSynthesis.cancel();
                
                // Show the selected UI
                document.querySelectorAll('[class^="ui-"]').forEach(section => {
                    section.style.display = 'none';
                });
                document.querySelector('.ui-' + mode).style.display = 'block';
                
                // Initialize the mode if needed
                if (mode === 'preview') {
                    initPreviewMode();
                } else if (mode === 'ar') {
                    initARMode();
                }
            });
        });*/

        // Home button functionality
        document.getElementById('home-link').addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all nav links
            document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
            // Add active class to home link
            this.classList.add('active');
            
            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
            
            // Switch to 2D mode if not already
            /*if (!document.querySelector('[data-mode="2d"]').classList.contains('active')) {
                document.querySelector('[data-mode="2d"]').click();
            }*/
            setMode('2d');
        });
        
        // REMOVE
        // Offer panel buttons
	document.getElementById('offer-add').addEventListener('click', (e) => {
	  e.preventDefault();
	  sfx('chime');
	  goToWallet();
	});

	document.getElementById('offer-copy').addEventListener('click', async () => {
	  sfx('chime');
	  try {
	    await navigator.clipboard.writeText("${walletDeepLink}");
	    const btn = document.getElementById('offer-copy');
	    const prev = btn.innerText;
	    btn.innerText = 'Copied!';
	    setTimeout(() => (btn.innerText = prev), 1200);
	  } catch {
	    alert('Copy failed. Long-press and copy the link instead.');
	  }
	});

	document.getElementById('offer-close').addEventListener('click', () => {
	  sfx('chime');
	  closeOfferPanel();
	});

	// Open panel from control bar
	document.getElementById('open-offer').addEventListener('click', () => {
	  sfx('chime');
	  openOfferPanel();
	});
	// REMOVE

        // Smooth scrolling for navigation links
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                if (this.getAttribute('href').startsWith('#')) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href');
                    
                    // Update active nav link
                    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
                    this.classList.add('active');
                    
                    // Scroll to section
                    const targetSection = document.querySelector(targetId);
                    if (targetSection) {
                        targetSection.scrollIntoView({ behavior: 'smooth' });
                    }
                }
            });
        });

        // Form submission handler
        document.getElementById('contact-form').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Thank you for your message! We will get back to you soon.');
            this.reset();
        });

        // Sound toggle functionality
        /*function setupSoundToggle(buttonId, soundEnabled = false) {
            const button = document.getElementById(buttonId);
            if (!button) return;
            
            button.addEventListener('click', () => {
                soundEnabled = !soundEnabled;
                const icon = button.querySelector('i');
                icon.className = soundEnabled ? 'fas fa-volume-up' : 'fas fa-volume-mute';
                button.innerHTML = icon.outerHTML + ' ' + (soundEnabled ? 'Sound On' : 'Sound Off');
                
                console.log('Sound ' + (soundEnabled ? 'enabled' : 'disabled'));
            });
        }*/
        function bindSoundButton(id) {
	    var btn = document.getElementById(id);
	    if (!btn) return;
	    btn.addEventListener('click', function(){
	      setSoundEnabled(!audio.enabled);
	      sfx('chime'); // audible confirmation
	    }, { passive: true });
	}
	bindSoundButton('sound-toggle');
	bindSoundButton('ar-sound-toggle');
	setSoundEnabled(false);
	
	// ar fixed
	// === AR overlay buttons ===
	const arGetBtn = document.getElementById('ar-get-credential');
	if (arGetBtn) {
	  arGetBtn.addEventListener('click', () => {
	    sfx('chime');
	    goToWallet();   // wallet deeplink func
	  });
	}

	/*const arReplayBtn = document.getElementById('ar-replay-instructions');
	if (arReplayBtn) {
	  arReplayBtn.addEventListener('click', () => {
	    sfx('chime');
	    clearTyping('ar-instruction-box');
	    typeInstruction(
	      "To interact with the orbs and crystals you can scroll, drag and zoom in and out with your fingers or controller. Look for the glowing credential orb. Aim at it and press your controller trigger, tap it with your fingers, or press the Get Credential button.",
	      'ar-instruction-box'
	    );
	  });
	}*/
	const arReplayBtn = document.getElementById('ar-replay-instructions');
	if (arReplayBtn) {
	  arReplayBtn.addEventListener('click', () => {
	    sfx('chime');
	    clearTyping('ar-instruction-box');

	    // Replay exactly what was last typed in AR, or fall back to a sensible message.
	    const msg =
	      lastInstruction['ar-instruction-box'] ||
	      (navigator.xr
		? "Preparing AR… if nothing happens, your device/browser may not support WebXR."
		: "WebXR not available. Use a supported browser/device.");

	    typeInstruction(msg, 'ar-instruction-box');
	  });
	}
  
	
	// Exit AR button
	const exitBtn = document.getElementById('exit-ar');
	if (exitBtn) {
	  exitBtn.addEventListener('click', () => {
	    sfx('chime');
	    
	    const boxId = 'ar-instruction-box'; // typing fix
	    if (window.__xrSession){ 
	      window.__xrSession.end();
	    } else {
	      // no session (e.g., on unsupported devices) - still show the text -- typing fix
	      clearTyping(boxId);
	      typeInstruction("AR session ended. Tap ‘Enter AR’ to start again.", boxId);
	    }
	    // fall back to preview or 2D UI after exit
	    document.body.classList.remove('ar-active');
	    //setMode('preview');
	    // fix message as we exit ar
	    window.__suppressPreviewTyping = true;
	    setTimeout(() => {
	      setMode('preview');
	      window.__suppressPreviewTyping = false;
	    }, 5000);
	  });
	}
	
	// end ar fixed


        // Setup sound toggles
        //setupSoundToggle('sound-toggle');
        //setupSoundToggle('ar-sound-toggle');

        

        // 3D Preview Mode Initialization
	function initPreviewMode() {
	  // Re-showing the mode? Just retype instructions and bail.
	  const instructions =
	    "Welcome! Tap the glowing orb (or press Get Credential) to open your wallet and accept the offer. You can rotate the scene by dragging.";

	  if (previewInit) {
	    //clearTyping('instruction-box');
	    //typeInstruction(instructions, 'instruction-box');
	    if (!window.__suppressPreviewTyping) {     // <-- guard
	      clearTyping('instruction-box');
	      typeInstruction(instructions, 'instruction-box');
	    }
	    
	    // Set href for panel button (and keep click working)
	    document.getElementById('offer-add').setAttribute('href', "${walletDeepLink}");
	    
	    return;
	  }
	  previewInit = true;

	  // Scene
	  const canvas = document.getElementById('preview-canvas');
	  const scene = new THREE.Scene();
	  scene.background = new THREE.Color(0x0f0c29);

	  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
	  renderer.setSize(canvas.clientWidth, canvas.clientHeight);

	  const camera = new THREE.PerspectiveCamera(75, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
	  camera.position.z = 5;

	  const controls = new THREE.OrbitControls(camera, renderer.domElement);
	  controls.enableDamping = true;
	  controls.dampingFactor = 0.05;

	  // Lights
	  scene.add(new THREE.AmbientLight(0xffffff, 0.55));
	  const dir = new THREE.DirectionalLight(0xffffff, 0.9);
	  dir.position.set(5, 5, 5);
	  scene.add(dir);

	  // Existing centerpiece
	  const geometry = new THREE.IcosahedronGeometry(1, 0);
	  const material = new THREE.MeshPhongMaterial({
	    color: 0x4361ee,
	    emissive: 0x3a0ca3,
	    shininess: 100,
	    specular: 0x4cc9f0
	  });
	  const mainObject = new THREE.Mesh(geometry, material);
	  scene.add(mainObject);

	  // Orbiting spheres
	  const smallGeom = new THREE.SphereGeometry(0.3, 16, 16);
	  const smallMaterial = new THREE.MeshPhongMaterial({ color: 0xf72585 });
	  for (let i = 0; i < 5; i++) {
	    const s = new THREE.Mesh(smallGeom, smallMaterial);
	    const radius = 2.5;
	    const angle = (i / 5) * Math.PI * 2;
	    s.position.set(Math.cos(angle) * radius, Math.sin(angle) * radius * 0.5, Math.sin(angle) * radius * 0.5);
	    scene.add(s);
	  }

	  // === Credential Orb (clickable) ===
	  const orbMat = new THREE.MeshStandardMaterial({
	    color: 0xf72585,
	    emissive: 0x4cc9f0,
	    emissiveIntensity: 0.45,
	    metalness: 0.2,
	    roughness: 0.25
	  });
	  clickableOrb = new THREE.Mesh(new THREE.SphereGeometry(0.35, 32, 32), orbMat);
	  clickableOrb.position.set(0, -0.2, 1.2);
	  scene.add(clickableOrb);

	  // Raycaster for hover/click
	  raycaster = new THREE.Raycaster();
	  pointer = new THREE.Vector2();

	  function updatePointer(e) {
	    const rect = renderer.domElement.getBoundingClientRect();
	    const x = ( (e.clientX - rect.left) / rect.width ) * 2 - 1;
	    const y = - ( (e.clientY - rect.top) / rect.height ) * 2 + 1;
	    pointer.set(x, y);
	  }

	  let hovering = false;
	  function checkHover() {
	    raycaster.setFromCamera(pointer, camera);
	    const hit = raycaster.intersectObject(clickableOrb, false).length > 0;
	    if (hit !== hovering) {
	      hovering = hit;
	      renderer.domElement.style.cursor = hovering ? 'pointer' : 'default';
	      orbMat.emissiveIntensity = hovering ? 0.9 : 0.45;
	      if (hovering) sfx('tick');
	    }
	  }

	  renderer.domElement.addEventListener('pointermove', (e) => { updatePointer(e); checkHover(); }, { passive: true });
	  renderer.domElement.addEventListener('click', (e) => {
	    updatePointer(e); checkHover();
	    if (hovering) {
	      sfx('chime');
	      goToWallet();
	    }
	  });

	  // Animate
	  function animate(t) {
	    requestAnimationFrame(animate);
	    // gentle motion
	    mainObject.rotation.x += 0.005;
	    mainObject.rotation.y += 0.01;
	    clickableOrb.scale.setScalar(1 + Math.sin(t * 0.004) * 0.08);

	    controls.update();
	    renderer.render(scene, camera);
	  }
	  animate(0);

	  // Resize
	  window.addEventListener('resize', () => {
	    camera.aspect = canvas.clientWidth / canvas.clientHeight;
	    camera.updateProjectionMatrix();
	    renderer.setSize(canvas.clientWidth, canvas.clientHeight);
	  });

	  // Initial instructions
	  clearTyping('instruction-box');
	  typeInstruction(instructions, 'instruction-box');

	  // Set href for panel button (and keep click working--update phase 4 ui)
	  document.getElementById('offer-add').setAttribute('href', "${walletDeepLink}");

	  
	  //openOfferPanel();
	  
	  document.getElementById('replay-instructions').onclick = function(){
	      sfx('chime');
	      if ('speechSynthesis' in window) window.speechSynthesis.cancel();
	      clearTyping('instruction-box');
	      typeInstruction(instructions, 'instruction-box');
	    };

	    document.getElementById('enter-ar').onclick = function(){
	      sfx('chime');
	      setMode('ar');
	      // start ar fixed -- 
	      if (navigator.xr && window.__startImmersiveAR) {
	        window.__startImmersiveAR();
	      } else {
	        // fallback message if XR is not ready
	        clearTyping('ar-instruction-box');
	        typeInstruction("Preparing AR… if nothing happens, your device/browser may not support WebXR AR.", 'ar-instruction-box');
	      } // fixed ar --
	    };
	    
	    const btn2d = document.getElementById('btn-2d-get-credential');
	    if (btn2d) btn2d.addEventListener('click', () => sfx('chime'));
	}
        
	// AR Mode Initialization (real WebXR)
	function initARMode(autoStart = false) {
	  /*const canvas = document.getElementById('ar-canvas');
	  const boxId = 'ar-instruction-box';
	  
	  //say this as an immediate instruction or overwrite it with webxr not available
	  clearTyping(boxId);
	  typeInstruction(
	    "Preparing AR… if nothing happens, your device/browser may not support WebXR.",
	    boxId
	  );


	  clearTyping(boxId);*/
	  const canvas = document.getElementById('ar-canvas');
	  const boxId = 'ar-instruction-box';

	  clearTyping(boxId);
	  const msg = navigator.xr
	    ? "Preparing AR… if nothing happens, your device/browser may not support WebXR."
	    : "WebXR not available. Use a supported browser/device.";
	  typeInstruction(msg, boxId, 40);

	  if (!navigator.xr) return;

	  if (!navigator.xr) {
	    typeInstruction("WebXR not available. Use a supported browser/device.", boxId, 40);
	    return;
	  }

	  // Build Three scene
	  const scene = new THREE.Scene();

	  const renderer = new THREE.WebGLRenderer({
	    canvas,
	    antialias: true,
	    alpha: true,                // transparent bg for passthrough
	    preserveDrawingBuffer: false,
	    powerPreference: 'high-performance'
	  });
	  renderer.xr.enabled = true;
	  renderer.xr.setReferenceSpaceType('local-floor');
	  renderer.setPixelRatio(window.devicePixelRatio);
	  renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
	  renderer.setClearColor(0x000000, 0); // fully transparent
	  renderer.autoClear = false;

	  const camera = new THREE.PerspectiveCamera();

	  // Lighting
	  scene.add(new THREE.AmbientLight(0xffffff, 0.6));
	  const dir = new THREE.DirectionalLight(0xffffff, 0.8);
	  dir.position.set(1,1,1);
	  scene.add(dir);

	  // === Same "center + orbiters" ===
	  const group = new THREE.Group();
	  scene.add(group);

	  const center = new THREE.Mesh(
	    new THREE.IcosahedronGeometry(0.1, 0),
	    new THREE.MeshPhongMaterial({
	      color: 0x4361ee,
	      emissive: 0x3a0ca3,
	      shininess: 100
	    })
	  );
	  group.add(center);

	  const orbiters = [];
	  const smallGeom = new THREE.SphereGeometry(0.03, 16, 16);
	  const smallMat  = new THREE.MeshPhongMaterial({ color: 0xf72585 });
	  for (let i = 0; i < 5; i++) {
	    const s = new THREE.Mesh(smallGeom, smallMat);
	    orbiters.push(s);
	    group.add(s);
	  }
	  
	  // ar fixed -- adding the glowing orb
	  const orbMatAR = new THREE.MeshStandardMaterial({
	      color: 0xf72585,
	      emissive: 0x4cc9f0,
	      emissiveIntensity: 1.0,
	      metalness: 0.2,
	      roughness: 0.25
	  });
	  const clickableOrbAR = new THREE.Mesh(
	      new THREE.SphereGeometry(0.09, 36, 36),
	      orbMatAR
	  ); // 
	  // place just in front of the cluster
	  clickableOrbAR.position.set(0, -0.05, 0.35);
	  group.add(clickableOrbAR);
	  
	  // end ar fixed

	  // Keep content ~1.5m in front of the viewer (HUD-like, no hit-test needed)
	  function placeInFrontOfViewer(refSpace, frame) {
	    const pose = frame.getViewerPose(refSpace);
	    if (!pose) return;
	    const { position: p, orientation: o } = pose.transform;
	    const q = new THREE.Quaternion(o.x, o.y, o.z, o.w);
	    const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(q);
	    const pos = new THREE.Vector3(p.x, p.y, p.z).add(forward.multiplyScalar(1.5));
	    group.position.copy(pos);
	  }

	  let session = null;
	  const raycasterAR = new THREE.Raycaster(); // ar fixed
	  
	  let hudDistance = 1.5;  // meters in front of viewer
	  let hudYaw = 0;         // manual rotation around Y

	  function placeInFrontOfViewer(refSpace, frame) {
	  const pose = frame.getViewerPose(refSpace);
	  if (!pose) return;
	    const { position: p, orientation: o } = pose.transform;
	    const q = new THREE.Quaternion(o.x, o.y, o.z, o.w);
	    const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(q);
	    const pos = new THREE.Vector3(p.x, p.y, p.z).add(forward.multiplyScalar(hudDistance));
	    group.position.copy(pos);
	    group.rotation.set(0, hudYaw, 0);
	  }
	  
	  // Simple rotate (1 finger) + pinch-distance (2 fingers) on the AR canvas
	function attachARGestures() {
	  const active = new Map(); // pointerId -> {x,y}
	  let lastPinch = null;

	  function onDown(e) {
	    if (e.target !== canvas) return;
	    active.set(e.pointerId, { x: e.clientX, y: e.clientY });
	    canvas.setPointerCapture(e.pointerId);
	    if (active.size === 2) lastPinch = pinchMeasure();
	  }

	  function onMove(e) {
	    if (!active.has(e.pointerId)) return;
	    const pt = active.get(e.pointerId);
	    const dx = e.clientX - pt.x;
	    const dy = e.clientY - pt.y;
	    pt.x = e.clientX; pt.y = e.clientY;

	    if (active.size === 1) {
	      // horizontal drag rotates HUD left/right
	      hudYaw += dx * 0.005;
	    } else if (active.size === 2) {
	      const cur = pinchMeasure();
	      const delta = cur.dist - (lastPinch ? lastPinch.dist : cur.dist);
	      // move closer/farther with pinch
	      hudDistance = Math.max(0.6, Math.min(3.0, hudDistance - delta * 0.003));
	      lastPinch = cur;
	    }
	  }

	  function onUp(e) {
	    if (active.has(e.pointerId)) {
	      active.delete(e.pointerId);
	      try { canvas.releasePointerCapture(e.pointerId); } catch {}
	    }
	    if (active.size < 2) lastPinch = null;
	  }

	  function pinchMeasure() {
	    const pts = [...active.values()];
	    const dx = pts[0].x - pts[1].x;
	    const dy = pts[0].y - pts[1].y;
	    return { dist: Math.hypot(dx, dy) };
	  }

	  canvas.addEventListener('pointerdown', onDown);
	  canvas.addEventListener('pointermove', onMove);
	  canvas.addEventListener('pointerup', onUp);
	  canvas.addEventListener('pointercancel', onUp);

	  // return a disposer so we can clean up on session end
	  return () => {
	    canvas.removeEventListener('pointerdown', onDown);
	    canvas.removeEventListener('pointermove', onMove);
	    canvas.removeEventListener('pointerup', onUp);
	    canvas.removeEventListener('pointercancel', onUp);
	  };
	} // end ar updates


	  async function startSession() {
	    try {
	      if (window.__xrStarting || window.__xrSession) return;
    	      window.__xrStarting = true;
	      const supported = await navigator.xr.isSessionSupported('immersive-ar');
	      if (!supported) {
		typeInstruction("‘immersive-ar’ not supported on this setup.", boxId, 40);
		return;
	      }

	      session = await navigator.xr.requestSession('immersive-ar', {
		requiredFeatures: ['local-floor'],
		// keep DOM UI on top if device supports it
		optionalFeatures: ['dom-overlay', 'hit-test'],
		domOverlay: { root: document.body }
	      });

	      await renderer.xr.setSession(session);
	      const detachGestures = attachARGestures(); // ar updates
	      
	      // document.body.classList.add('ar-active'); // ar updates- removed for css
	      window.__xrSession = session;

	      typeInstruction(
		"AR started. Try to drag, scroll and zoom with your fingers or controller. Look ahead for the credential orb. Press your controller trigger to open the wallet.",
		boxId
	      );

	      // Trigger = open wallet
	      /*session.addEventListener('select', () => {
		sfx('chime');
		goToWallet();   // whenever go to wallet deep link
	      });*/
	      session.addEventListener('select', (ev) => {
	      // Ray from the controller toward the scene
	      const ref = renderer.xr.getReferenceSpace();
	      const pose = ev.frame.getPose(ev.inputSource.targetRaySpace, ref);
	      if (!pose) return;

	      const { position: p, orientation: o } = pose.transform;

	      // Build a THREE.Ray from position + orientation
	      const origin = new THREE.Vector3(p.x, p.y, p.z);
	      const dir = new THREE.Vector3(0, 0, -1); // -Z forward in local space
	      const q = new THREE.Quaternion(o.x, o.y, o.z, o.w);
	      dir.applyQuaternion(q).normalize();

	      raycasterAR.set(origin, dir);
	      const hits = raycasterAR.intersectObject(clickableOrbAR, true);

	      if (hits.length > 0) {
	        sfx('chime');
	        goToWallet();           // only when the orb is actually selected
	      } else {
	        sfx('tick');            // feedback but no action
	        clearTyping('ar-instruction-box');
	        typeInstruction("Aim for the glowing orb and press to open the wallet.", 'ar-instruction-box');
	      }
	      });

	      session.addEventListener('end', () => {
		renderer.setAnimationLoop(null);
		typeInstruction("AR session ended. Tap ‘Enter AR’ to start again.", boxId);
		//document.body.classList.remove('ar-active'); // ar updates- removed for css and control is back to setmode
		window.__xrSession = null; // ar updates
		detachGestures && detachGestures(); // ar updates
	      });

	      // Animate in XR time
	      renderer.setAnimationLoop((time, frame) => {
		center.rotation.y += 0.01;
		orbiters.forEach((s, i) => {
		  const R = 0.25 + i*0.02;
		  const t = time * 0.001 + i;
		  s.position.set(Math.cos(t)*R, Math.sin(t*0.7)*R*0.6, Math.sin(t)*R);
		});
		// pulse the orb to make it obvious
		const tt = time * 0.001;
		const pulse = 1 + Math.sin(tt * 2.2) * 0.1;
		clickableOrbAR.scale.setScalar(pulse);
		orbMatAR.emissiveIntensity = 0.9 + Math.max(0, Math.sin(tt * 2.2)) * 0.5;


		if (frame) {
		  const ref = renderer.xr.getReferenceSpace();
		  placeInFrontOfViewer(ref, frame);
		}

		renderer.render(scene, camera);
	      });

	    } catch (err) {
	      console.error('AR start failed:', err);
	      typeInstruction("Failed to start AR: " + err.message, boxId);
	    }
	  }

	  // expose a starter so we can call it directly from the Enter AR button click
	  window.__startImmersiveAR = startSession;

	  // auto-start if explicitly requested (kept for flexibility)
	  if (autoStart) startSession();

	  // keep canvas sizing normal outside XR too
	  window.addEventListener('resize', () => {
	    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
	  });
	}

        
        // Initialize the default mode (2D)
        document.querySelector('.ui-2d').style.display = 'block';
    </script>
</body>
</html>`);
});  

// JWKS endpoint for issuer public key
app.get('/.well-known/jwks.json', (req, res) => {
  const jwk = keyPair.publicKey.export({ format: 'jwk' });
  res.json({
    keys: [{
      ...jwk,
      kid: currentKid,
      use: 'sig',
      alg: 'ES256'
    }]
  });
});

/**
 * OID4VCI Section 6: Token Endpoint
 * 
 * Accepts application/x-www-form-urlencoded
 * Supports grant_type = "urn:ietf:params:oauth:grant-type:pre-authorized_code".
 * Issues access_token and returns c_nonce / c_nonce_expires_in (for later proof at /credential).
 * 
 * OAuth 2.0 Attestation-Based Client Authentication [draft-ietf-oauth-attestation-based-client-auth-07]
 * PoP check via 'Client-Attestation-PoP' header (aka client-attestation-pop)
 * parsing of 'Client-Attestation' header and enforcing cnf key binding
 * Implements OAuth 2.0 with extensions for:
 * - Proof-of-Possession (PoP) token verification
 * - Client attestation for high assurance
 * - Pre-authorized code grant flow
 * - Anti-replay protection with JTI tracking
 */
app.post('/token', async (req, res) => {
  const trace = req.headers['x-trace'] || `tr_${Math.random().toString(16).slice(2,8)}`;
  const now = () => Date.now();                 // ms clock for timings
  const nowSec = () => Math.floor(now() / 1000); // seconds clock for JWT checks
  const T = { t_token_recv: now() };
  console.log(`[timing][issuer][${trace}] token_recv`);

  T.t_pop_verify_start = now();

  // checks as described in OAuth 2.0 Attestation-Based Client Authentication [draft-ietf-oauth-attestation-based-client-auth-07]
  // headers
  const pop = req.get('client-attestation-pop');       // PoP JWT
  const att = req.get('client-attestation');           // Attestation JWT 
  if (!pop) return res.status(401).json({ error: 'missing_client_pop' });

  const b64json = (s) => JSON.parse(Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'));

  // Parse PoP JWT header and payload
  let popHeader, popPayload;
  try {
    const [h, p] = pop.split('.');
    popHeader = b64json(h);
    popPayload = b64json(p);
  } catch {
    return res.status(400).json({ error: 'malformed_pop' });
  }
  if (!popHeader.jwk) return res.status(400).json({ error: 'missing_pop_jwk' });

  // Verify PoP signature using presented JWK
  try {
    const key = await importJWK(popHeader.jwk, popHeader.alg || 'ES256');
    await jwtVerify(pop, key);
  } catch (e) {
    console.error('[token] invalid PoP signature:', e.message);
    return res.status(401).json({ error: 'invalid_pop_signature' });
  }

  // Required claims on PoP
  // Validating PoP claims per OID4VCI requirements
  const expectedAud = new URL('/token', ISSUER_BASE_URL).toString();
  const nowS = nowSec();
  if (popPayload.aud !== expectedAud) return res.status(401).json({ error: 'bad_pop_audience' });
  if (!popPayload.iat || !popPayload.exp || popPayload.iat > nowS || popPayload.exp <= nowS) {
    return res.status(401).json({ error: 'bad_pop_times' });
  }
  // freshness window (5 min)
  if ((nowS - popPayload.iat) > 300) return res.status(401).json({ error: 'stale_pop' });
  if (!popPayload.jti) return res.status(401).json({ error: 'missing_pop_jti' });

  // Anti-replay cache
  // In-memory jti cache (demo purposes). For production, use a store (e.g., Redis) per deployment.
  globalThis.__seenJti ||= new Map(); // jti -> expAt(ms)
  const seenJti = globalThis.__seenJti;
  if (seenJti.has(popPayload.jti)) return res.status(401).json({ error: 'pop_replay' });
  seenJti.set(popPayload.jti, popPayload.exp * 1000);
  globalThis.__replayPruner ||= setInterval(() => {
    const t = now();
    for (const [j, expAt] of seenJti) if (t > expAt) seenJti.delete(j);
  }, 60_000);

  // Optional attestation parse & cnf binding - high assurance
  if (att) {
    try {
      const [ah, ap] = att.split('.');
      const attHeader = b64json(ah);
      const attPayload = b64json(ap);
      if (attPayload.aud && attPayload.aud !== ISSUER_BASE_URL) {
        return res.status(401).json({ error: 'bad_att_audience' });
      }
      const cnfJwk = attPayload?.cnf?.jwk;
      if (cnfJwk) {
        const canon = (j) => JSON.stringify({ crv:j.crv, kty:j.kty, x:j.x, y:j.y });
        if (canon(cnfJwk) !== canon(popHeader.jwk)) {
          return res.status(401).json({ error: 'cnf_mismatch' });
        }
      }
    } catch (e) {
      console.warn('[token] attestation parse failed (not enforced):', e.message);
    }
  }

  T.t_pop_verify_end = now();
  console.log(`[timing][issuer][${trace}] pop_verify dur=${T.t_pop_verify_end - T.t_pop_verify_start}ms`);

  // token, sec.6
  const body = req.body || {};
  const grant_type = body.grant_type;
  const preAuth = body['pre-authorized_code'] ?? body.pre_authorized_code;

  if (grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const offer = credentialOffers.get(preAuth);
  if (!offer || offer.status !== 'pending') {
    return res.status(400).json({ error: 'invalid_grant' });  // spec error codes
  }
  // OID4VCI: Return c_nonce so the wallet can prove key possession at /credential (sec.7).
  const accessToken = `token_${crypto.randomBytes(32).toString('hex')}`;
  const cNonce = crypto.randomBytes(16).toString('hex');

  credentialOffers.set(preAuth, {
    ...offer,
    status: 'token_issued',
    accessToken,
    cNonce, 
    createdAt: offer.createdAt || now()
  });

  res.set('Cache-Control','no-store');
  res.set('Pragma','no-cache');

  console.log(`[timing][issuer][${trace}] token_issued dur=${now() - T.t_token_recv}ms`);

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    c_nonce: cNonce,
    c_nonce_expires_in: 300
  });
});

// ---- debug helpers (small + self-contained) ----
const dbg = (...args) => console.log.apply(console, args);

// used in /credential
function decodeJwtNoVerify(jwt) {
  try {
    const [h, p] = jwt.split('.');
    const b64 = s => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return { header: JSON.parse(b64(h)), payload: JSON.parse(b64(p)) };
  } catch (e) {
    return { header: null, payload: null, error: e.message };
  }
}
function trunc(s, n = 140) {
  if (typeof s !== 'string') return s;
  return s.length > n ? s.slice(0, n) + '…' : s;
}
// -----------------------------------------------

/**
 * OID4VCI Section 8: Credential Endpoint
 * Expects a Bearer access token issued by /token for the same offer.
 * Verifies a proof JWT from the Wallet bound to the current c_nonce
 * Issues an SD-JWT-based credential and returns a fresh c_nonce for any
 * subsequent calls (OID4VCI).
 * `protectedHeader.typ` must be 'openid4vci-proof+jwt'
 * `payload.aud` is checked and must equal the issuer identifier.
 * Basic 5-minute freshness check on `iat` - implementation specific
 * Formats: Accepts request `format` of 'dc+sd-jwt' or legacy 'vc+sd-jwt'
 * Always returns a credential with header `typ: 'dc+sd-jwt'` as per
 * draft-ietf-oauth-sd-jwt-vc (rename note).
 * Issues SD-JWT Verifiable Credentials
 */
app.post('/credential', async (req, res) => {
  const trace = req.headers['x-trace'] || `tr_${Math.random().toString(16).slice(2,8)}`;
  const now = () => Date.now();
  const T = { t_issue_recv: now() };
  console.log(`[timing][issuer][${trace}] issue_recv`);


  // logs
  dbg("---- DEBUG ISSUER [/credential] ----");
  dbg("Headers.authorization:", trunc(req.headers.authorization || '(none)'));
  dbg("Requested format:", req.body?.format, "vct:", req.body?.vct);
  dbg("Incoming proof object:", req.body?.proof);
  dbg("Public JWK received:", JSON.stringify(req.body?.proof?.public_key_jwk || null, null, 2));
  dbg("PoP JWT received:", trunc(req.body?.proof?.jwt || '(none)', 300));
  dbg("-------------------------------------");

  // Bearer token verification per OAuth 2.0
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  const accessToken = authHeader.slice(7);

  // Find valid credential offer session
  let offer;
  for (const [, data] of credentialOffers.entries()) {
    if (data.accessToken === accessToken && data.status === 'token_issued') {
      offer = data; break;
    }
  }
  if (!offer) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  // Accept format from wallet; we issue dc+sd-jwt 
  const requestedFormat = req.body.format;
  if (requestedFormat && requestedFormat !== 'dc+sd-jwt' && requestedFormat !== 'vc+sd-jwt') {
    return res.status(400).json({ error: 'unsupported_credential_format' });
  }

  // PoP OID4VCI
  const proof = req.body.proof || {};
  if (!proof.jwt) {
    return res.status(400).json({ error: 'invalid_proof' }); //error codes
  }

  let subjectJwk;

  T.t_proof_verify_start = now();
  
  try {
    // Verify proof JWT. The holder key can be in header.jwk or in body proof.public_key_jwk
    const { payload, protectedHeader } = await jwtVerify(proof.jwt, async (header) => {
      const jwkFromHeader = header.jwk;
      const jwkFromBody = proof.public_key_jwk;
      const jwk = jwkFromHeader || jwkFromBody;
      if (!jwk) throw new Error('No JWK provided in proof');

      subjectJwk = jwk;
      return await importJWK(jwk, header.alg || 'ES256');
    });
    
    // logs on verify
    const decodedPoP = decodeJwtNoVerify(proof.jwt);
    dbg("[proof] decoded PoP header:", decodedPoP.header);
    dbg("[proof] decoded PoP payload:", decodedPoP.payload);
    dbg(`[proof] nonce matches offer.cNonce=${offer.cNonce}`);


    // Header MUST be this typ
    // typ: REQUIRED. MUST be openid4vci-proof+jwt, which explicitly types the 
    // key proof JWT as recommended in Section 3.11 of [RFC8725]. sec.F.1
    if (protectedHeader.typ && protectedHeader.typ !== 'openid4vci-proof+jwt') {
      throw new Error('unexpected_type');
    }

    // Nonce - prevent replay
    if (payload.nonce !== offer.cNonce) {
      throw new Error('invalid_proof_nonce');
    }

    // Audience validation
    // aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer Identifier. sec.F.1
    if (payload.aud && payload.aud !== ISSUER_BASE_URL) {
      throw new Error('bad_audience');
    }

    // freshness check: 5 min
    if (payload.iat && Math.abs((Date.now() / 1000) - payload.iat) > 300) {
      throw new Error('stale_iat');
    }

  } catch (e) {
    console.error('PoP verification failed:', e);
    return res.status(400).json({ error: 'invalid_proof' });
  }
  
  T.t_proof_verify_end = now();
  console.log(`[timing][issuer][${trace}] proof_verify dur=${T.t_proof_verify_end - T.t_proof_verify_start}ms`);

  // ---- Issue SD-JWT-VC (dc+sd-jwt) ----
  try {
    const vct = req.body.vct || 'UniversityDegreeCredential';
    //const sdJwt = await createVerifiableCredential(offer.sessionId, subjectJwk, vct);
    const sdJwt = await createVerifiableCredential(offer.sessionId, subjectJwk, vct, { trace });

    offer.status = 'credential_issued';

    // Rotate c_nonce for next call (recommended)
    const nextCnonce = crypto.randomBytes(16).toString('hex');
    offer.cNonce = nextCnonce;
    offer.cNonceIssuedAt = Date.now();

    // Cleanup expired sessions
    cleanupExpiredEntries(sessions, 300000);

    // logs what wallet asked/ was returned
    dbg("[cred] Issued dc+sd-jwt for session:", offer.sessionId);
    dbg("[cred] Next c_nonce (for future proof):", offer.cNonce);

    console.log(`[timing][issuer][${trace}] issue_done total=${now() - T.t_issue_recv}ms`);

    res.json({
      format: 'dc+sd-jwt',
      credential: sdJwt,
      c_nonce: nextCnonce,
      c_nonce_expires_in: 300
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'credential_issuance_failed' });
  }
});

// Helper for cleanup
function cleanupExpiredEntries(map, maxAge) {
  const now = Date.now();
  for (const [key, entry] of map.entries()) {
    if (now - entry.createdAt > maxAge) {
      map.delete(key);
    }
  }
}

/**
 * SD-JWT Verifiable Credential Creation
 * Implements draft-ietf-oauth-sd-jwt-vc-12 with:
 * Selective disclosure via per-claim salts + digest list (returned as JWT~disclosures).
 * 'vct' claim to identify the credential type
 * 'cnf.jwk' binding the Holder key (key confirmation).
 * VC Data Model 2.0 structure and contexts
 * - Key confirmation through cnf claim
 * - Revocation support through status list
 */
// SD-JWT final
//async function createVerifiableCredential(sessionId, subjectJwk, vct = 'UniversityDegreeCredential') {
async function createVerifiableCredential(sessionId, subjectJwk, vct = 'UniversityDegreeCredential', timingCtx = null) {

  const session = sessions.get(sessionId);
  if (!session) throw new Error('Invalid session');

  // Student data -- assume we have a db, this is a sample for demo purposes
  const studentData = {
    studentId: "S1234567",
    fullName: "Jane Johnson",
    major: "Computer Science",
    enrollmentStatus: "full-time",
    university: "Technical University",
    courses: ["CS101", "CS202", "MATH301"],
    enrollmentDate: "2023-09-01",
    expectedGraduation: "2027-06-15"
  };

  // Subject ID
  const subjectId = `urn:example:student:${studentData.studentId}`;

  // Build SD-JWT disclosures
  const disclosures = [];
  const sdDigests = [];
  const selectiveClaims = ['studentId','enrollmentStatus','fullName', 'major', 'courses', 'enrollmentDate', 'expectedGraduation'];

  for (const claim of selectiveClaims) {
    const salt = base64url.encode(crypto.randomBytes(16)); // per claim salts
    const disclosure = [salt, claim, studentData[claim]];
    const disclosureB64 = base64url.encode(JSON.stringify(disclosure));
    const digest = base64url.encode(crypto.createHash('sha256').update(disclosureB64).digest());
    disclosures.push(disclosureB64);
    sdDigests.push(digest);
  }

  //SD-JWT VC does not require VCDM JSON-LD 'vc' object with W3C VCDM 2.0-style for interoperability 
  // REVOCATION UPDATES SD-JWT-VC payload
  const jti = `urn:vc:${crypto.randomBytes(16).toString('hex')}`;
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = nowSec + 365 * 24 * 60 * 60; // 1 year validity

  const payload = {
    iss: ISSUER_BASE_URL,
    iat: nowSec,
    exp: expSec,
    jti, // Unique identifier for revocation
    vct,
    vc: { 
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1'
      ],
      type: ['VerifiableCredential', vct],
      credentialSubject: {
        id: subjectId,
        university: studentData.university, // in the context of immerse, always disclosed
        _sd: sdDigests, // selective disclosures
        _sd_alg: 'sha-256'
      },
      credentialStatus: {
        id: `${ISSUER_BASE_URL}/.well-known/credential-status.json`,
        type: 'StatusList2025', // not W3C "Status List 2021" format. Verifiers quote by jti.
        statusPurpose: 'revocation'
      }
    },
    cnf: { jwk: subjectJwk } // Key confirmation per OID4VCI
  };
  // REVOCATION UPDATES END

  const __vcSignStart = Date.now();
  //T.t_vc_sign_start = now();
  // Sign as SD-JWT-VC
  const signedJwt = await new SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dc+sd-jwt',
      kid: currentKid
    })
    .sign(keyPair.privateKey);
    
    //T.t_vc_sign_end = now();
    //console.log(`[timing][issuer][${trace}] vc_sign dur=${T.t_vc_sign_end - T.t_vc_sign_start}ms`);
    if (timingCtx?.trace) {
      const __vcSignEnd = Date.now();
      console.log(`[timing][issuer][${timingCtx.trace}] vc_sign dur=${__vcSignEnd - __vcSignStart}ms`);
    }
    
    // logs
    dbg("[sd-jwt] selective claims:", selectiveClaims);
	  dbg("[sd-jwt] sdDigests:", sdDigests);
	  dbg("[sd-jwt] disclosures (decoded, first 5 shown):");
	  disclosures.slice(0,5).forEach((d, i) => {
	  try {
	    const raw = JSON.parse(Buffer.from(d.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'));
	    dbg(`  #${i}`, raw); // [salt, claimName, claimValue]
	  } catch (e) {
	    dbg(`  #${i} (decode error)`, e.message);
	  }
	});
	if (disclosures.length > 5) dbg(`[sd-jwt] …and ${disclosures.length-5} more disclosures`);
	
	//logs
	const decodedVC = decodeJwtNoVerify(signedJwt);
	dbg("[sd-jwt] signed JWT typ=dc+sd-jwt kid=", currentKid);
	dbg("[sd-jwt] VC header:", decodedVC.header);
	dbg("[sd-jwt] VC payload (top-level):", decodedVC.payload);
	dbg("[sd-jwt] VC payload.vc.credentialSubject keys:", Object.keys(decodedVC.payload?.vc?.credentialSubject || {}));
	
	//logs to be removed
	const sdJwtFinal = [signedJwt, ...disclosures].join('~'); // show what i return
	dbg(`[sd-jwt] final sd-jwt length=${sdJwtFinal.length} chars, parts=JWT + ${disclosures.length} disclosures`);



  // Final SD-JWT object: JWT + disclosures, i.e. JWT ~ disclosure1 ~ disclosure2 ~ ...
  return [signedJwt, ...disclosures].join('~');
}

/**
 * Server Initialization and Key Management
 * Generates an ES256 key pair on startup.
 * Registers the public JWK in the central registry (supporting service, see repo docs).
 * Session cleanup for resource management
 * Health monitoring for production readiness
 */
async function startServer() {
  try {
    keyPair = generateKeyPair();
    console.log('Generated signing keys');
    
    // Register key with central registry
    await registerKey();
    
    // Start periodic key rotation (every 24 hours)
    setInterval(async () => {
      keyPair = generateKeyPair();
      await registerKey();
      console.log('Rotated signing keys');
    }, 24 * 60 * 60 * 1000);
    
    // Start cleanup scheduler
    setInterval(() => {
      cleanupExpiredEntries(sessions, 300000);
      cleanupExpiredEntries(credentialOffers, 300000);
    }, 60000);

    app.listen(port, () => {
      console.log(`VC Issuer running at ${ISSUER_BASE_URL}`);
      console.log(`Pod: ${POD_NAME}`);
      console.log(`Start the flow at ${ISSUER_BASE_URL}/authorize`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();
