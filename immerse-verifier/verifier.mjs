/**
 * IMMERSE OID4VP Verifier - Implementation Notes
 *
 * Specs & drafts implemented in this Verifier:
 * - OpenID for Verifiable Presentations (OID4VP)
 *   Request by reference (wallet fetches Request Object via request_uri)
 *   response_mode=direct_post with response_uri callback
 *   Nonce/state correlation and replay prevention
 *   (Optional but implemented here) .well-known/openid-configuration for discovery
 *
 * - SD-JWT-based Verifiable Credentials (SD-JWT VC) draft
 *   Accepts SD-JWT VCs where header.typ may be 'dc+sd-jwt' (new) or 'vc+sd-jwt' (legacy)
 *   Verifies disclosure digests: credentialSubject._sd / _sd_alg (sha-256) against provided disclosures
 *
 * - Holder Binding
 *   VP signer key (VP header.jwk) MUST match VC holder binding (vc.cnf.jwk) (which is present in this implementation)
 *   Enforced via JWK thumbprint comparison (RFC7638)
 *
 * - Issuer Trust / JOSE
 *   VC signature verification using Issuer's JWKS at /.well-known/jwks.json
 *   Fallback to demo key registry when Issuer JWKS is unavailable or has a new signing key (implementation specific)
 *
 * - Expiration & Revocation
 *   Rejects expired credentials (exp)
 *   Checks a simple Issuer-published status list at /.well-known/credential-status.json and denies if VC jti appears in revoked[]
 *
 * Notes on SD-JWT media type alignment:
 * - The SD-JWT VC draft renamed its media type from 'vc+sd-jwt' to 'dc+sd-jwt'.
 *   For interoperability during transition, this verifier accepts both values,
 *   while the Issuer emits 'dc+sd-jwt'. See the Issuer's implementation notes
 *   for the rename rationale and transitional acceptance. (Kept consistent for the IMMERSE Verifier.)
 *
 * - Demo front end (2D / 3D / AR) to launch wallet deep links and show the flow
 *
 * See also: IMMERSE VC Issuer (OID4VCI) notes for complementary details on formats,
 * media types, and status list. This Verifier is aligned with that Issuer's outputs.
 */

import express from 'express';
import { jwtVerify, importJWK, calculateJwkThumbprint } from 'jose';
import crypto from 'crypto';
import base64url from 'base64url';
import axios from 'axios';
import cors from 'cors'; // redirect to classroom session -- VR learning use case

const app = express();
const port = 5000;
app.use(express.json()); // fix
app.use(express.urlencoded({ extended: false })); // for response_mode=direct_post

const VERIFIER_BASE_URL = process.env.VERIFIER_BASE_URL || `http://localhost:${port}`;
const KEY_REGISTRY_URL = process.env.KEY_REGISTRY_URL || 'http://localhost:8080';
const WALLET_FRONTEND_URL = process.env.WALLET_FRONTEND_URL || `ADD HERE YOUR WALLET FR URL AND PORT`;
const CLASSROOM_BASE_URL = process.env.CLASSROOM_BASE_URL || VERIFIER_BASE_URL || 'https://classroom.example.com'; // VR learning use case


const verificationSessions = new Map(); // Spec: must store nonce/state for replay prevention 
const classroomSessions = new Map(); // map for classroom sessions -- VR learning use case

// Cleanup for expired sessions -- Cleans up verification sessions -- OID4VP
const cleanupExpiredSessions = () => {
  const now = Date.now();
  for (const [sessionId, session] of verificationSessions.entries()) {
    if (now - session.createdAt > 15 * 60 * 1000) { // 15 min expiration
      verificationSessions.delete(sessionId);
    }
  }
};

// Cleanup interval expired sessions
setInterval(cleanupExpiredSessions, 5 * 60 * 1000); // Clean every 5 min

// Cleanup for classroom sessions -- Cleans up classroom sessions (used after successful verification) -- VR learning use case
const cleanupClassroomSessions = () => {
  const now = Date.now();
  for (const [token, session] of classroomSessions.entries()) {
    if (now > session.expiresAt) {
      classroomSessions.delete(token);
    }
  }
};

setInterval(cleanupClassroomSessions, 5 * 60 * 1000); // Clean every 5 min -- VR learning use case

// redirect for classroom session -- VR learning use case
app.use(cors({
    origin: true, 
    credentials: true
})); // NOTE: origin:true allows any origin; change to whitelist in prod from TLS + CORS security guidance

// Health endpoints
app.get('/healthz', (req, res) => res.status(200).send('OK'));
app.get('/readyz', (req, res) => res.status(200).send('OK'));

/*
 * SD-JWT VC verification helper
 * Splits "compactJWT~disclosure1~disclosure2~..."
 * Discovers Issuer from payload for key lookup
 * Verifies VC JWS using Issuer key (Issuer JWKS first, registry fallback)
 * Accepts header.typ in {'dc+sd-jwt','vc+sd-jwt'} to accomodate media-type transition
 * Recomputes each disclosure digest and checks presence in _sd (sha-256)
 * Returns: { payload, protectedHeader, disclosedClaims } with merged claims
 */
async function verifySdJwt(sdJwt) {
  // sdJwt expected format: compactJwt~disclosure1~disclosure2...  
  // Follows SD-JWT format (IETF SD-JWT VC)
  const parts = sdJwt.split('~');
  const jwt = parts[0];
  const disclosures = parts.slice(1);

  // Decode payload to discover the issuer (for key discovery only)
  const unvPayload = JSON.parse(base64url.decode(jwt.split('.')[1] || ''));
  const iss = unvPayload.iss; // key discovery-implementation considerations

  const { payload, protectedHeader } = await jwtVerify(jwt, async (header) => {
    if (!header.kid) throw new Error('Missing kid in VC header');

    // 1) Try issuer-local JWKS
    try {
      const jwksRes = await axios.get(`${iss}/.well-known/jwks.json`);
      const key = (jwksRes.data.keys || []).find(k => k.kid === header.kid);
      if (key) return importJWK(key, header.alg || 'ES256');
    } catch (_) { /* ignore and fall back */ }

    // 2) Fallback to central registry (implementation specific)
    const reg = await axios.get(`${KEY_REGISTRY_URL}/.well-known/jwks.json`);
    const key = (reg.data.keys || []).find(k => k.kid === header.kid);
    if (!key) throw new Error(`Issuer key not found for kid ${header.kid}`); // no key found -fail

    return importJWK(key, header.alg || 'ES256');
  });

  // Accept both old & new media types
  if (protectedHeader.typ && !['dc+sd-jwt','vc+sd-jwt'].includes(protectedHeader.typ)) {
    throw new Error(`Unexpected VC typ: ${protectedHeader.typ}`);
  }

  // Verify selective disclosures
  if (payload?.vc?.credentialSubject?._sd) {
    const sdDigests = payload.vc.credentialSubject._sd;
    const sdAlg = payload.vc.credentialSubject._sd_alg || 'sha-256';

    for (const disclosure of disclosures) {
      const digest = sdAlg === 'sha-256'
        ? base64url.encode(crypto.createHash('sha256').update(disclosure).digest())
        : (() => { throw new Error(`Unsupported hash algorithm: ${sdAlg}`) })();

      if (!sdDigests.includes(digest)) {
        throw new Error('Disclosure not found in SD digests');
      }
    }
  }

  // Extract disclosed claims
  const disclosedClaims = {};
  for (const disclosure of disclosures) {
    try {
      const [salt, claim, value] = JSON.parse(base64url.decode(disclosure)); // SD-JWT disclosure format parsing
      disclosedClaims[claim] = value;
    } catch (e) {
      console.error('Error parsing disclosure:', e);
    }
  }

  return { payload, protectedHeader, disclosedClaims }; // returns issuer-verified VC payload and disclosed claims
}

/* 
 * Generate presentation request -- modified to match VR learning use case 
 * Creates a new verification session with nonce + state
 * Encodes a presentation_definition for the use case (studentId + enrollmentStatus)
 * Uses response_mode=direct_post and response_uri callback per OID4VP
 * Exposes the Request Object via GET /request/:sessionId (request_uri)
 * so the IMMERSE wallet will resolve openid://?request_uri=... to fetch it
 */ 
function generatePresentationRequest() {
  const sessionId = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex'); // nonce MUST be unpredictable and tied to session (13.6.1)
  const state = crypto.randomBytes(16).toString('hex'); // state used for correlation (CSRF protection) // Spec: 5.1 / 13.6 (state/nonce)
  
  const presentationRequest = {
    client_id: VERIFIER_BASE_URL,
    response_type: 'vp_token',
    response_mode: 'direct_post',
    scope: 'openid',
    nonce,
    state,
    //redirect_uri: `${VERIFIER_BASE_URL}/presentation-callback`, // fallback
    response_uri: `${VERIFIER_BASE_URL}/presentation-callback`,
    presentation_definition: {
      id: 'virtual_classroom_access',
      purpose: 'Verify your enrollment status for classroom access',
      format: {
        'dc+sd-jwt': { alg: ['ES256'] },
        'vc+sd-jwt': { alg: ['ES256'] },
        'jwt_vc':    { alg: ['ES256'] }
      },
      input_descriptors: [{
        id: 'student_identification',
        purpose: 'Verification of student ID',
        constraints: {
          fields: [
            { path: ['$.vc.credentialSubject.studentId'], filter: { type: 'string' } }
          ]
        }
      },
      {
        id: 'enrollment_status',
        purpose: 'Verification of student enrollment status',
        constraints: {
          fields: [
            { path: ['$.vc.credentialSubject.enrollmentStatus'],
              filter: { type: 'string', pattern: 'full-time|part-time' } }
          ]
        }
      }]
    }
  };


  verificationSessions.set(sessionId, {
    nonce,
    state,
    createdAt: Date.now(),
    status: 'pending',
    presentationDefinition: presentationRequest.presentation_definition
  });

  return {
    sessionId,
    request: base64url.encode(JSON.stringify(presentationRequest))
  };
}

// Home page 
app.get('/', async (req, res) => {
  const { sessionId, request } = generatePresentationRequest();
  
  const requestUri = `${VERIFIER_BASE_URL}/request/${sessionId}`;
  const openidReq = `openid://?request_uri=${encodeURIComponent(requestUri)}`;
  const walletVerificationLink = `${WALLET_FRONTEND_URL}/?verification_request=${encodeURIComponent(openidReq)}`;
  const DOCS_URL = process.env.DOCS_URL || 'https://github.com/excid-io/immerse-dev';

  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Immersive Classroom Access (Verifier)</title>
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
            vertical-align: middle; /* align the buttons in the middle */
            padding: 12px 28px;
            background: var(--primary);
            color: white;
            border: 1px solid transparent; /*border: none;*/
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
            text-decoration: none;
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
            text-decoration: none;
        }

        .control-btn i {
            margin-right: 8px;
        }

        .control-btn:hover {
            background: rgba(255, 255, 255, 0.2);
            text-decoration: none;
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
        
        /* AR specific styles */
        :root { --ar-controls-h: 84px; }
        
        /* Make AR view sharp & unobstructed */
        body.ar-active .ui-ar.card {
            background: transparent;
            border: 0;
            backdrop-filter: none;
            box-shadow: none;
            padding: 0;
        }

        body.ar-active #ar-container {
            height: calc(100svh - var(--ar-controls-h));
            margin: 0;
            border-radius: 0;
        }
        
        body.ar-active #ar-container .instruction-box {
            bottom: 16px;
            pointer-events: none;
            z-index: 10;
            background: rgba(0,0,0,0.40);
        }

        body.ar-active .ui-ar .simulation-controls {
            position: relative;
            z-index: 20;
            margin-top: 0;
            padding-top: 12px;
            background: transparent;
        }
        
        #ar-canvas { touch-action: none; }
        
        #ar-container {
            position: relative;
        }
        
        /* Mobile tweaks */
        @media (max-width: 640px) {
            .simulation-controls {
                flex-wrap: wrap;
                gap: 10px 10px;
                justify-content: center;
                padding: 8px 12px;
            }
            .simulation-controls .control-btn {
                flex: 1 1 calc(50% - 10px);
                min-width: 140px;
                justify-content: center;
            }
            .instruction-box { max-width: min(90vw, 420px); }
            
            .container { padding: 12px; }
            
            header {
                flex-direction: column;
                align-items: center;
                gap: 8px;
            }

            .logo {
                font-size: clamp(18px, 6vw, 22px);
                line-height: 1.15;
            }
            
            nav ul {
                flex-wrap: wrap;
                justify-content: center;
                gap: 8px 10px;
                margin-top: 6px;
            }
            nav li { margin: 0; }
            nav a {
                padding: 8px 12px;
                font-size: 14px;
                border-radius: 14px;
            }
            nav a i { margin-right: 6px; font-size: 14px; }

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

            .card { padding: 18px; }
            #canvas-container { height: min(55vh, 360px); }

            input, textarea { font-size: 16px; }
        }

        ul {
            margin-left: 20px;
            margin-bottom: 15px;
        }
        
        ul li {
            margin-bottom: 8px;
            color: rgba(255, 255, 255, 0.8);
        }
        
        form label {
            display: block;
            margin-bottom: 5px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        form input, form textarea {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(255, 255, 255, 0.1);
            color: white;
            margin-bottom: 15px;
        }
        
        form input:focus, form textarea:focus {
            outline: none;
            border-color: var(--primary);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
            	<i class="fa-solid fa-shield-halved logo-icon" aria-hidden="true"></i>
            	<!-- i class="fa-solid fa-user-check logo-icon" aria-hidden="true"></i -->
                <!-- i class="fas fa-shield-check logo-icon"></i -->
                <span>Immersive Classroom Verifier</span>
            </div>
            <nav>
                <ul>
                    <li><a href="#" class="active" id="home-link"><i class="fas fa-home"></i> Home</a></li>
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
            <h1>Verify to Enter the Virtual Classroom</h1>
            <p>Use your wallet to present your enrollment credential. Once verified, you'll be redirected into the AR classroom.</p>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-lock"></i></div>
                    <h3>Secure</h3>
                    <p>Verification includes cryptographic checks to ensure each credential is valid, untampered, and issued by a trusted Issuer.</p>
                </div>
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-bolt"></i></div>
                    <h3>Instant</h3>
                    <p>Verification takes seconds with OpenID for Verifiable Presentations (OID4VP).</p>
                </div>
                <div class="feature">
                    <div class="feature-icon"><i class="fas fa-user-shield"></i></div>
                    <h3>Private</h3>
                    <p>Selective disclosure lets you reveal only what's needed.</p>
                </div>
            </div>
            
            <a id="btn-verify" href="${walletVerificationLink}" class="btn"><i class="fas fa-shield-check"></i> Verify Now</a>
            <a href="${DOCS_URL}" class="btn btn-secondary"><i class="fas fa-book"></i> Learn More</a>
            
            <p style="margin-top: 20px; color: rgba(255, 255, 255, 0.7); font-size: 14px;">
                <i class="fas fa-lightbulb"></i> Tip: On a phone or headset with WebXR, the AR mode lets you select a floating orb to open your wallet.
            </p>
        </section>

        <!-- 3D Preview UI -->
        <section class="ui-preview card">
            <h1>3D Preview Experience</h1>
            <p>Experience what the AR verification would look like. In this simulation, you can interact with 3D objects and see how the process would work in augmented reality.</p>
            
            <div id="canvas-container">
                <canvas id="preview-canvas"></canvas>
                <div class="instruction-box" id="instruction-box"></div>
            </div>
            
            <div class="simulation-controls">
                <button class="control-btn" id="sound-toggle"><i class="fas fa-volume-mute"></i> Sound Off</button>
                <button class="control-btn" id="replay-instructions"><i class="fas fa-redo"></i> Replay Instructions</button>
                <a class="control-btn" id="open-wallet-preview" href="${walletVerificationLink}"><i class="fas fa-shield-check"></i> Verify Now</a>
                <button class="control-btn" id="enter-ar"><i class="fas fa-glasses"></i> Enter AR</button>
            </div>
        </section>

        <!-- AR Experience UI -->
        <section class="ui-ar card">
            <h1>AR Verification Experience</h1>
            <p>Put on your AR headset to experience credential verification in augmented reality. Follow the instructions to verify your credential and access the classroom.</p>
            
            <div id="ar-container">
                <canvas id="ar-canvas"></canvas>
                <div class="instruction-box" id="ar-instruction-box">
                    <!-- AR instructions will be typed here -->
                </div>
            </div>
            
            <div class="simulation-controls">
                <button class="control-btn" id="ar-sound-toggle"><i class="fas fa-volume-mute"></i> Sound Off</button>
                <a class="control-btn" id="ar-get-credential" href="${walletVerificationLink}"><i class="fas fa-shield-check"></i> Verify Now</a>
                <button class="control-btn" id="ar-replay-instructions"><i class="fas fa-redo"></i> Replay Instructions</button>
                <button class="control-btn" id="exit-ar"><i class="fas fa-times"></i> Exit AR</button>
            </div>
        </section>

        <!-- About Section -->
        <section id="about" class="card">
            <h2><i class="fas fa-info-circle"></i> About Our Verifier</h2>
            <p>This verifier uses OID4VP to check cryptographic proofs from your wallet and confirm your classroom access. It pairs with our issuer to keep everything interoperable and secure.</p>
            <p>Our mission is to make credential verification seamless, secure, and accessible to everyone.</p>
        </section>

        <!-- Contact Section -->
        <section id="contact" class="card">
            <h2><i class="fas fa-envelope"></i> Contact Us</h2>
            <p>Questions about verification or access? Send us a note and we'll get back to you.</p>
            <form id="contact-form">
                <div style="margin-bottom: 15px;">
                    <label for="name"><i class="fas fa-user"></i> Name:</label>
                    <input type="text" id="name">
                </div>
                <div style="margin-bottom: 15px;">
                    <label for="email"><i class="fas fa-envelope"></i> Email:</label>
                    <input type="email" id="email">
                </div>
                <div style="margin-bottom: 15px;">
                    <label for="message"><i class="fas fa-comment"></i> Message:</label>
                    <textarea id="message" rows="4"></textarea>
                </div>
                <button type="submit" class="btn"><i class="fas fa-paper-plane"></i> Send Message</button>
            </form>
        </section>

        <footer>
            <p>2025 Immersive Classroom Verifier | Powered by ExcID | Funded by SPIRIT</p>
        </footer>
    </div>
    <script>
        // Audio and voice setup
        const audio = { ctx: null, gain: null, enabled: false };
        
        function ensureAudioCtx() {
            if (!audio.ctx) {
                audio.ctx = new (window.AudioContext || window.webkitAudioContext)();
                audio.gain = audio.ctx.createGain();
                audio.gain.gain.value = 0.25;
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
                    let activeElId = null;
                    if (document.querySelector('.ui-preview') && document.querySelector('.ui-preview').style.display !== 'none') {
                        activeElId = 'instruction-box';
                    } else if (document.querySelector('.ui-ar') && document.querySelector('.ui-ar').style.display !== 'none') {
                        activeElId = 'ar-instruction-box';
                    }
                    const text = activeElId ? lastInstruction[activeElId] : null;
                    if (text) { 
                        if ('speechSynthesis' in window) window.speechSynthesis.cancel(); 
                        speak(text); 
                    }
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
            o.connect(g); 
            g.connect(audio.gain);

            if (kind === 'tick') {
                o.type = 'square';
                o.frequency.setValueAtTime(1200, now);
                g.gain.setValueAtTime(0.08, now);
                g.gain.exponentialRampToValueAtTime(0.001, now + 0.06);
                o.start(now); 
                o.stop(now + 0.08);
            } else {
                o.type = 'sine';
                o.frequency.setValueAtTime(880, now);
                o.frequency.exponentialRampToValueAtTime(440, now + 0.22);
                g.gain.setValueAtTime(0.12, now);
                g.gain.exponentialRampToValueAtTime(0.001, now + 0.24);
                o.start(now); 
                o.stop(now + 0.26);
            }
        }

        function updateSoundButtons() {
            ['sound-toggle','ar-sound-toggle'].forEach(function(id){
                const btn = document.getElementById(id);
                if (!btn) return;
                btn.innerHTML = '<i class="' + (audio.enabled ? 'fas fa-volume-up' : 'fas fa-volume-mute') + '"></i> ' + (audio.enabled ? 'Sound On' : 'Sound Off');
            });
        }
        
        // Voice synthesis setup
        let selectedVoice = null;
        const VOICE_PREFERENCE = [
            'Microsoft Aria Online (Natural) - English (United States)',
            'Microsoft Jenny Online (Natural) - English (United States)',
            'Microsoft Guy Online (Natural)',
            'Google US English',
            'Google UK English Female',
            'Google UK English Male',
            'Samantha', 'Ava', 'Alex', 'Victoria', 'Karen', 'Daniel'
        ];
        const VOICE_LANGS = ['en-US','en-GB','en-AU','en-CA'];

        function pickVoice() {
            const voices = window.speechSynthesis.getVoices();
            if (!voices || !voices.length) return null;

            for (const name of VOICE_PREFERENCE) {
                const v = voices.find(v => v.name === name);
                if (v) return v;
            }
            
            for (const hint of VOICE_PREFERENCE) {
                const v = voices.find(v => v.name.toLowerCase().includes(hint.toLowerCase()));
                if (v) return v;
            }
            
            const byLang = voices.find(v => VOICE_LANGS.includes((v.lang || '').trim()));
            return byLang || voices[0];
        }

        function initVoiceOnce() {
            if (!('speechSynthesis' in window) || selectedVoice) return;
            const haveNow = window.speechSynthesis.getVoices();
            if (haveNow && haveNow.length) {
                selectedVoice = pickVoice();
            } else {
                window.speechSynthesis.onvoiceschanged = () => {
                    if (!selectedVoice) selectedVoice = pickVoice();
                };
            }
        }
        initVoiceOnce();

        function speak(text) {
            if (!audio.enabled) return;
            if (!('speechSynthesis' in window)) return;

            initVoiceOnce();
            try {
                window.speechSynthesis.cancel();
                const u = new SpeechSynthesisUtterance(text);
                if (selectedVoice) u.voice = selectedVoice;
                u.rate = 0.95;
                u.pitch = 1.0;
                u.volume = 1.0;
                window.speechSynthesis.speak(u);
            } catch (e) {
                console.warn('TTS error:', e);
            }
        }
        
        // Typing functionality
        const typingState = {};
        const lastInstruction = {};

        function clearTyping(elementId) {
            const st = typingState[elementId];
            if (st && st.timer) clearTimeout(st.timer);
            typingState[elementId] = null;
        }

        function typeInstruction(text, elementId, speed = 40) {
            const el = document.getElementById(elementId);
            if (!el) return;

            lastInstruction[elementId] = text;
            clearTyping(elementId);

            if ('speechSynthesis' in window) window.speechSynthesis.cancel();
            speak(text);

            const token = Symbol('typing');
            typingState[elementId] = { token: token, timer: null };

            el.innerHTML = '';
            const tn = document.createTextNode('');
            el.appendChild(tn);

            let i = 0;
            const tickEvery = 3;
            
            function step() {
                const st = typingState[elementId];
                if (!st || st.token !== token) return;
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
            if ('speechSynthesis' in window) window.speechSynthesis.cancel();

            document.querySelectorAll('.mode-btn').forEach(function(btn){
                btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
            });

            document.querySelectorAll('[class^="ui-"]').forEach(function(sec){
                sec.style.display = 'none';
            });
            
            const show = document.querySelector('.ui-' + mode);
            if (show) show.style.display = 'block';

            if (mode === 'preview') initPreviewMode();
            
            if (mode === 'ar') {
                document.body.classList.add('ar-active');
                setArControlsHeight();
                initARMode(true);
            } else {
                document.body.classList.remove('ar-active');
            }
        }

        function setArControlsHeight() {
            const controls = document.querySelector('.ui-ar .simulation-controls');
            if (!controls) return;
            const h = controls.offsetHeight + 12;
            document.documentElement.style.setProperty('--ar-controls-h', h + 'px');
        }

        window.addEventListener('resize', setArControlsHeight);
        if ('fonts' in document) document.fonts.ready.then(setArControlsHeight);
        document.addEventListener('DOMContentLoaded', setArControlsHeight);

        document.querySelectorAll('.mode-btn').forEach(function(button){
            button.addEventListener('click', function(){
                const m = button.getAttribute('data-mode');
                sfx('chime');
                setMode(m);
            });
        });

        // Home button functionality
        document.getElementById('home-link').addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
            this.classList.add('active');
            window.scrollTo({ top: 0, behavior: 'smooth' });
            setMode('2d');
        });

        // Smooth scrolling for navigation links
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                if (this.getAttribute('href').startsWith('#')) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href');
                    
                    document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
                    this.classList.add('active');
                    
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
        function bindSoundButton(id) {
            const btn = document.getElementById(id);
            if (!btn) return;
            btn.addEventListener('click', function(){
                setSoundEnabled(!audio.enabled);
                sfx('chime');
            }, { passive: true });
        }
        
        bindSoundButton('sound-toggle');
        bindSoundButton('ar-sound-toggle');
        setSoundEnabled(false);
        
        // AR button functionality
        const arGetBtn = document.getElementById('ar-get-credential');
        if (arGetBtn) {
            arGetBtn.addEventListener('click', () => {
                sfx('chime');
                window.location.href = "${walletVerificationLink}";
            });
        }

        const arReplayBtn = document.getElementById('ar-replay-instructions');
        if (arReplayBtn) {
            arReplayBtn.addEventListener('click', () => {
                sfx('chime');
                clearTyping('ar-instruction-box');
                const msg = lastInstruction['ar-instruction-box'] ||
                    (navigator.xr
                        ? "Preparing AR& if nothing happens, your device/browser may not support WebXR."
                        : "WebXR not available. Use a supported browser/device.");
                typeInstruction(msg, 'ar-instruction-box');
            });
        }

        const exitBtn = document.getElementById('exit-ar');
        if (exitBtn) {
            exitBtn.addEventListener('click', () => {
                sfx('chime');
                const boxId = 'ar-instruction-box';
                if (window.__xrSession){ 
                    window.__xrSession.end();
                } else {
                    clearTyping(boxId);
                    typeInstruction("AR session ended. Tap 'Enter AR' to start again.", boxId);
                }
                document.body.classList.remove('ar-active');
                window.__suppressPreviewTyping = true;
                setTimeout(() => {
                    setMode('preview');
                    window.__suppressPreviewTyping = false;
                }, 500);
            });
        }
        
let previewInit = false;
let raycaster, pointer, clickableOrb;

function initPreviewMode() {
  const instructions =
    "Welcome! Find the glowing VERIFY orb and click it to open your wallet. You can rotate and zoom freely around all objects - even go through them to see from the inside!";

  if (previewInit) {
    if (!window.__suppressPreviewTyping) {
      clearTyping('instruction-box');
      typeInstruction(instructions, 'instruction-box');
    }
    return;
  }
  previewInit = true;

  const canvas = document.getElementById('preview-canvas');
  const container = document.getElementById('canvas-container');

  // Check if required elements exist
  if (!canvas || !container) {
    console.error('Required DOM elements not found');
    return;
  }

  canvas.style.width = '100%';
  canvas.style.height = '100%';

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0f0c29);

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  // Reduce near clipping plane to allow camera to get very close/through objects
  const camera = new THREE.PerspectiveCamera(75, 1, 0.01, 1000);
  camera.position.set(0, 0, 7);

  function sizeRendererToContainer() {
    const w = container.clientWidth || 800;
    const h = container.clientHeight || 500;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  sizeRendererToContainer();
  window.addEventListener('resize', sizeRendererToContainer);

  const controls = new THREE.OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.05;
  
  // Allow camera to get very close and even inside objects
  controls.minDistance = 0.1;
  controls.maxDistance = 15;
  controls.minPolarAngle = 0;
  controls.maxPolarAngle = Math.PI;

  // lights
  scene.add(new THREE.AmbientLight(0xffffff, 0.8));
  const dir1 = new THREE.DirectionalLight(0xffffff, 0.6);
  dir1.position.set(5, 5, 5);
  scene.add(dir1);
  
  const dir2 = new THREE.DirectionalLight(0xffffff, 0.4);
  dir2.position.set(-5, -3, -5);
  scene.add(dir2);

  // --- centerpiece: torus knot -------------------
  const knot = new THREE.Mesh(
    new THREE.TorusKnotGeometry(1.0, 0.18, 200, 20, 2, 3),
    new THREE.MeshPhongMaterial({
      color: 0x2b77ff,
      emissive: 0x0b3a7a,
      specular: 0x88ccff,
      shininess: 110,
      transparent: true,
      opacity: 0.9
    })
  );
  knot.scale.setScalar(0.85);
  scene.add(knot);

  // --- rings -------------------
  const ringR = 1.9;
  const ringT = 0.03;
  const ringMat = new THREE.MeshPhongMaterial({
    color: 0x2dd4bf,
    emissive: 0x0c6e62,
    shininess: 80,
    transparent: true,
    opacity: 0.85
  });
  const ringGroup = new THREE.Group();
  scene.add(ringGroup);

  const ring1 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 16, 180), ringMat);
  ring1.rotation.x = Math.PI * 0.5;
  const ring2 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 16, 180), ringMat);
  ring2.rotation.y = Math.PI * 0.5;
  const ring3 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 16, 180), ringMat);
  ring3.rotation.z = Math.PI * 0.5;
  ringGroup.add(ring1, ring2, ring3);

  // --- starfield -----------------------------------------------------
  const starGeom = new THREE.BufferGeometry();
  const starCnt = 250;
  const starPos = new Float32Array(starCnt * 3);
  for (let i = 0; i < starCnt; i++) {
    const r = 10 + Math.random() * 12;
    const a = Math.random() * Math.PI * 2;
    const b = (Math.random() - 0.5) * Math.PI;
    starPos[i * 3 + 0] = r * Math.cos(a) * Math.cos(b);
    starPos[i * 3 + 1] = r * Math.sin(b);
    starPos[i * 3 + 2] = r * Math.sin(a) * Math.cos(b);
  }
  starGeom.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
  const stars = new THREE.Points(
    starGeom,
    new THREE.PointsMaterial({ color: 0x4cc9f0, size: 0.02, transparent: true, opacity: 0.7 })
  );
  scene.add(stars);

  // --- VERIFY orb --------------
  const orbMat = new THREE.MeshStandardMaterial({
    color: 0x00ff88,
    emissive: 0x4cc9f0,
    emissiveIntensity: 0.55,
    metalness: 0.35,
    roughness: 0.25
  });
  clickableOrb = new THREE.Mesh(new THREE.SphereGeometry(0.35, 32, 32), orbMat);
  clickableOrb.position.set(1.8, 1.2, 2.8);
  scene.add(clickableOrb);

  // --- interaction ----------------------------------------------------------
  raycaster = new THREE.Raycaster();
  pointer = new THREE.Vector2();

  function updatePointer(e) {
    const rect = renderer.domElement.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    const y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    pointer.set(x, y);
  }

  let hovering = false;
  function checkHover() {
    raycaster.setFromCamera(pointer, camera);
    const hit = raycaster.intersectObject(clickableOrb, false).length > 0;
    if (hit !== hovering) {
      hovering = hit;
      renderer.domElement.style.cursor = hovering ? 'pointer' : 'default';
      orbMat.emissiveIntensity = hovering ? 1.0 : 0.55;
      if (hovering) sfx('tick');
    }
  }

  renderer.domElement.addEventListener('pointermove', (e) => { 
    updatePointer(e); 
    checkHover(); 
  }, { passive: false });
  
  renderer.domElement.addEventListener('click', (e) => {
    updatePointer(e); 
    checkHover();
    if (hovering) {
      sfx('chime');
      window.location.href = "${walletVerificationLink}";
    }
  }, { passive: false });

  // --- animate --------------------------------------------------------------
  function animate(t) {
    requestAnimationFrame(animate);

    const tt = t * 0.001;
    knot.rotation.x += 0.0045;
    knot.rotation.y += 0.0090;

    ringGroup.rotation.x = Math.sin(tt * 0.7) * 0.22;
    ringGroup.rotation.y = Math.cos(tt * 0.6) * 0.22;

    stars.rotation.y += 0.0008;

    // orb pulse
    const pulse = 1 + Math.sin(t * 0.004) * 0.07;
    clickableOrb.scale.setScalar(pulse);

    controls.update();
    renderer.render(scene, camera);
  }
  animate(0);

  // --- UI hooks - Wait for DOM to be ready ----------------------------------
  setTimeout(() => {
    // Replay instructions button
    const replayBtn = document.getElementById('replay-instructions');
    if (replayBtn) {
      replayBtn.onclick = function () {
        sfx('chime');
        if ('speechSynthesis' in window) window.speechSynthesis.cancel();
        clearTyping('instruction-box');
        typeInstruction(instructions, 'instruction-box');
      };
    }

    // AR experience button
    const enterArBtn = document.getElementById('enter-ar');
    if (enterArBtn) {
      enterArBtn.onclick = function () {
        sfx('chime');
        setMode('ar');
        if (navigator.xr && window.__startImmersiveAR) {
          window.__startImmersiveAR();
        } else {
          clearTyping('ar-instruction-box');
          typeInstruction("Preparing AR… if nothing happens, your device/browser may not support WebXR AR.", 'ar-instruction-box');
        }
      };
    }

    // Other buttons
    const walletBtn = document.getElementById('open-wallet-preview');
    if (walletBtn) {
      walletBtn.addEventListener('click', () => sfx('chime'));
    }

    const verifyBtn = document.getElementById('btn-verify');
    if (verifyBtn) {
      verifyBtn.addEventListener('click', () => sfx('chime'));
    }
  }, 100);

  // --- UI initialization ----------------------------------------------------
  clearTyping('instruction-box');
  typeInstruction(instructions, 'instruction-box');
}

// Enhanced AR Mode Initialization
function initARMode(autoStart = false) {
    const canvas = document.getElementById('ar-canvas');
    const boxId = 'ar-instruction-box';

    clearTyping(boxId);
    const msg = navigator.xr
        ? "AR starting... Look around to place the verification portal in your space. Move close to interact!"
        : "WebXR not available. Use a supported browser/device with AR capabilities.";
    typeInstruction(msg, boxId, 40);

    if (!navigator.xr) return;

    const scene = new THREE.Scene();

    const renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: true,
        alpha: true,
        preserveDrawingBuffer: false,
        powerPreference: 'high-performance'
    });
    renderer.xr.enabled = true;
    renderer.xr.setReferenceSpaceType('local-floor');
    renderer.setPixelRatio(window.devicePixelRatio);
    renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
    renderer.setClearColor(0x000000, 0);
    renderer.autoClear = false;

    const camera = new THREE.PerspectiveCamera();

    // Enhanced lighting for immersive feel
    scene.add(new THREE.AmbientLight(0xffffff, 0.8));
    const mainLight = new THREE.DirectionalLight(0xffffff, 1.0);
    mainLight.position.set(5, 5, 5);
    scene.add(mainLight);
    
    const fillLight = new THREE.DirectionalLight(0x4cc9f0, 0.4);
    fillLight.position.set(-3, 2, -3);
    scene.add(fillLight);

    // Main AR content group - ar version of 3D preview
    const arSceneGroup = new THREE.Group();
    scene.add(arSceneGroup);

    // --- REPLICA OF 3D PREVIEW IN AR (with optimizations) ---

    // Centerpiece: Simplified torus knot for AR performance
    const knot = new THREE.Mesh(
        new THREE.TorusKnotGeometry(0.12, 0.03, 64, 8, 2, 3), // Reduced complexity
        new THREE.MeshPhongMaterial({
            color: 0x2b77ff,
            emissive: 0x0b3a7a,
            specular: 0x88ccff,
            shininess: 110,
            transparent: true,
            opacity: 0.9
        })
    );
    knot.scale.setScalar(0.8);
    arSceneGroup.add(knot);

    // rings for AR
    const ringR = 0.3;
    const ringT = 0.008;
    const ringMat = new THREE.MeshPhongMaterial({
        color: 0x2dd4bf,
        emissive: 0x0c6e62,
        shininess: 80,
        transparent: true,
        opacity: 0.85
    });
    
    const ringGroup = new THREE.Group();
    arSceneGroup.add(ringGroup);

    const ring1 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 12, 24), ringMat);
    ring1.rotation.x = Math.PI * 0.5;
    const ring2 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 12, 24), ringMat);
    ring2.rotation.y = Math.PI * 0.5;
    const ring3 = new THREE.Mesh(new THREE.TorusGeometry(ringR, ringT, 12, 24), ringMat);
    ring3.rotation.z = Math.PI * 0.5;
    ringGroup.add(ring1, ring2, ring3);

    // VERIFY Orb for AR 
    const orbMatAR = new THREE.MeshStandardMaterial({
        color: 0x00ff88,
        emissive: 0x4cc9f0,
        emissiveIntensity: 0.8,
        metalness: 0.4,
        roughness: 0.2
    });
    const verifyOrbAR = new THREE.Mesh(
        new THREE.SphereGeometry(0.08, 32, 32),
        orbMatAR
    );
    verifyOrbAR.position.set(0.25, 0.15, 0.4); // Positioned for easy access
    arSceneGroup.add(verifyOrbAR);

    // Add particle effects 
    const particleCount = 50;
    const particles = new THREE.BufferGeometry();
    const particlePositions = new Float32Array(particleCount * 3);
    const particleColors = new Float32Array(particleCount * 3);
    
    for (let i = 0; i < particleCount * 3; i += 3) {
        // Position particles in a sphere around the scene
        const radius = 0.6 + Math.random() * 0.3;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        
        particlePositions[i] = radius * Math.sin(phi) * Math.cos(theta);
        particlePositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta);
        particlePositions[i + 2] = radius * Math.cos(phi);
        
        // Blue-green particles
        particleColors[i] = 0.3 + Math.random() * 0.7;     // R
        particleColors[i + 1] = 0.8 + Math.random() * 0.2; // G  
        particleColors[i + 2] = 0.9 + Math.random() * 0.1; // B
    }
    
    particles.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    particles.setAttribute('color', new THREE.BufferAttribute(particleColors, 3));
    
    const particleMaterial = new THREE.PointsMaterial({
        size: 0.02,
        vertexColors: true,
        transparent: true,
        opacity: 0.6
    });
    
    const particleSystem = new THREE.Points(particles, particleMaterial);
    arSceneGroup.add(particleSystem);

    // AR placement and interaction
    let arContentPlaced = false;
    let hudDistance = 1.2;
    let hudYaw = 0;

    function placeInFrontOfViewer(refSpace, frame) {
        const pose = frame.getViewerPose(refSpace);
        if (!pose) return;
        
        const { position: p, orientation: o } = pose.transform;
        const q = new THREE.Quaternion(o.x, o.y, o.z, o.w);
        const forward = new THREE.Vector3(0, 0, -1).applyQuaternion(q);
        
        // Position at comfortable distance in front of user
        const pos = new THREE.Vector3(p.x, p.y + 0.3, p.z).add(forward.multiplyScalar(hudDistance));
        arSceneGroup.position.copy(pos);
        arSceneGroup.rotation.set(0, hudYaw, 0);
    }

    // Enhanced AR gesture controls
    function attachARGestures() {
        const active = new Map();
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
            pt.x = e.clientX; 
            pt.y = e.clientY;

            if (active.size === 1) {
                // Single finger: rotate
                hudYaw += dx * 0.005;
                // Also allow vertical adjustment
                hudDistance = Math.max(0.5, Math.min(3.0, hudDistance - dy * 0.005));
            } else if (active.size === 2) {
                // Pinch: zoom
                const cur = pinchMeasure();
                const delta = cur.dist - (lastPinch ? lastPinch.dist : cur.dist);
                hudDistance = Math.max(0.5, Math.min(3.0, hudDistance - delta * 0.003));
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

        return () => {
            canvas.removeEventListener('pointerdown', onDown);
            canvas.removeEventListener('pointermove', onMove);
            canvas.removeEventListener('pointerup', onUp);
            canvas.removeEventListener('pointercancel', onUp);
        };
    }

    let session = null;
    const raycasterAR = new THREE.Raycaster();
    
    async function startSession() {
        try {
            if (window.__xrStarting || window.__xrSession) return;
            window.__xrStarting = true;
            
            const supported = await navigator.xr.isSessionSupported('immersive-ar');
            if (!supported) {
                typeInstruction("AR not supported on this device. Try a different browser or device with AR capabilities.", boxId, 40);
                return;
            }

            session = await navigator.xr.requestSession('immersive-ar', {
                requiredFeatures: ['local-floor'],
                optionalFeatures: ['dom-overlay', 'hit-test'],
                domOverlay: { root: document.body }
            });

            await renderer.xr.setSession(session);
            const detachGestures = attachARGestures();
            
            window.__xrSession = session;

            typeInstruction(
                "AR experience started! Walk around the verification portal. Move close to the glowing orb and press trigger to verify. Use gestures to rotate and zoom.",
                boxId
            );

            // Enhanced controller interaction
            session.addEventListener('select', (ev) => {
                const ref = renderer.xr.getReferenceSpace();
                const pose = ev.frame.getPose(ev.inputSource.targetRaySpace, ref);
                if (!pose) return;

                const { position: p, orientation: o } = pose.transform;
                const origin = new THREE.Vector3(p.x, p.y, p.z);
                const dir = new THREE.Vector3(0, 0, -1);
                const q = new THREE.Quaternion(o.x, o.y, o.z, o.w);
                dir.applyQuaternion(q).normalize();

                raycasterAR.set(origin, dir);
                const hits = raycasterAR.intersectObject(verifyOrbAR, true);

                if (hits.length > 0) {
                    sfx('chime');
                    // Enhanced feedback
                    orbMatAR.emissiveIntensity = 2.0;
                    setTimeout(() => {
                        orbMatAR.emissiveIntensity = 0.8;
                        window.location.href = "${walletVerificationLink}";
                    }, 300);
                } else {
                    sfx('tick');
                    clearTyping('ar-instruction-box');
                    typeInstruction("Aim at the glowing green verification orb and press trigger to authenticate.", 'ar-instruction-box');
                }
            });

            // fix message ending too soon 
            session.addEventListener('end', () => {
                setTimeout(() => {
                    renderer.setAnimationLoop(null);
                    typeInstruction("AR session ended. Return to preview mode or tap 'Enter AR' to start again.", boxId);
                    window.__xrSession = null;
                    detachGestures && detachGestures();
                }, 5000);
	    });


            // Enhanced animation loop for immersive feel
            renderer.setAnimationLoop((time, frame) => {
                const t = time * 0.001;
                
                // Animate the torus knot
                knot.rotation.x += 0.008;
                knot.rotation.y += 0.012;
                
                // Animate the rings with gentle floating motion
                ringGroup.rotation.x = Math.sin(t * 0.5) * 0.3;
                ringGroup.rotation.y = Math.cos(t * 0.4) * 0.3;
                
                // Orb pulsing with enhanced effect
                const pulse = 1 + Math.sin(t * 2.5) * 0.15;
                verifyOrbAR.scale.setScalar(pulse);
                orbMatAR.emissiveIntensity = 0.8 + Math.max(0, Math.sin(t * 2.5)) * 0.7;

                // Particle animation
                const positions = particleSystem.geometry.attributes.position.array;
                for (let i = 0; i < positions.length; i += 3) {
                    // Gentle floating motion for particles
                    positions[i + 1] += Math.sin(t * 0.5 + i * 0.1) * 0.001;
                }
                particleSystem.geometry.attributes.position.needsUpdate = true;

                if (frame) {
                    const ref = renderer.xr.getReferenceSpace();
                    placeInFrontOfViewer(ref, frame);
                }

                renderer.render(scene, camera);
            });

        } catch (err) {
            console.error('AR start failed:', err);
            typeInstruction("Failed to start AR: " + err.message, boxId);
        } finally {
            window.__xrStarting = false;
        }
    }

    window.__startImmersiveAR = startSession;

    if (autoStart) startSession();

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

/* 
 * OpenID configuration endpoint (optional but recommended)
 * Advertises response_modes, supported VP formats (including dc+sd-jwt / vc+sd-jwt),
 * request_uri_parameter, optional for OID4VP
 */ 
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: VERIFIER_BASE_URL,
    response_types_supported: ['vp_token'],
    response_modes_supported: ['direct_post'],
    scopes_supported: ['openid'],
    presentation_definitions_supported: ['virtual_classroom_access'],
    request_uri_parameter_supported: true,
    vp_formats_supported: {
      'dc+sd-jwt': { alg: ['ES256'] },
      'vc+sd-jwt': { alg: ['ES256'] },
      'jwt_vc':    { alg: ['ES256'] }
    }
  });
});

/* 
 * Get presentation request -- VR learning use case updates
 * Wallet calls this to resolve the Request Object referenced by request_uri
 * Contains nonce/state and the exact presentation_definition used for checks
 * response_uri points to /presentation-callback (direct_post receiver)
 */ 
app.get('/request/:sessionId', (req, res) => {
  const session = verificationSessions.get(req.params.sessionId);
  if (!session) return res.status(404).send('Session not found');
  
  res.json({
    client_id: VERIFIER_BASE_URL,
    nonce: session.nonce,
    state: session.state,
    response_uri: `${VERIFIER_BASE_URL}/presentation-callback`, 
    presentation_definition: {
      id: 'virtual_classroom_access',
      purpose: 'Verify your enrollment status for classroom access',
      format: {
        'dc+sd-jwt': { alg: ['ES256'] },
        'vc+sd-jwt': { alg: ['ES256'] },
        'jwt_vc':    { alg: ['ES256'] }
      },
      input_descriptors: [{
        id: 'student_identification',
        purpose: 'Verification of student ID',
        constraints: {
          fields: [
            { path: ['$.vc.credentialSubject.studentId'], filter: { type: 'string' } }
          ]
        }
      },
      {
        id: 'enrollment_status',
        purpose: 'Verification of student enrollment status',
        constraints: {
          fields: [
            { path: ['$.vc.credentialSubject.enrollmentStatus'],
              filter: { type: 'string', pattern: 'full-time|part-time' } }
          ]
        }
      }]
    }
  });
});

const REQUIRED_CLAIMS = new Set(['studentId', 'enrollmentStatus']);

/* 
 * OID4VP direct_post callback (response_mode=direct_post)
 * Incoming form body: vp_token (required), state, (optional) presentation_submission
 * Verification steps:
 * 1) Verify VP signature using header.jwk from VP (holder's key)
 * 2) Correlate with session via state and bind vpPayload.nonce to session.nonce
 * 3) Ensure definition_id matches request
 * 4) For each VC in vp_token:
 *    - If SD-JWT VC: use verifySdJwt(), check disclosure digests, merge claims
 *    - Else (JWT VC): verify JWS with Issuer key (Issuer JWKS, then registry)
 *    - Enforce holder binding: vp header.jwk thumbprint == vc.cnf.jwk thumbprint
 *    - Enforce validity windows (exp) and check Issuer's revocation status list
 * 5) Ensure required claims are disclosed (e.g. in this use case studentId, enrollmentStatus)
 * 6) On success, go to a short-lived classroom session and return redirect_url
 * Timing logs (demo): records VP, VC, and revocation check durations
 */ 
app.post('/presentation-callback', async (req, res) => {

  const trace = req.headers['x-trace'] || `tr_${Math.random().toString(16).slice(2,8)}`;
  const now = () => Date.now();
  const T = { t_cb_recv: now() };
  console.log(`[timing][verifier][${trace}] cb_recv`);

  const { vp_token, state } = req.body;
  if (!vp_token) return res.status(400).json({ error: 'missing_vp_token' });

  try {
    T.t_vp_verify_start = now();
    
    // Verify VP (holder-signed)
    const { payload: vpPayload, protectedHeader } = await jwtVerify(vp_token, async (header) => {
      if (!header.jwk) throw new Error('Missing JWK in VP header');
      return importJWK(header.jwk, header.alg || 'ES256');
    });
    
    T.t_vp_verify_end = now();
    console.log(`[timing][verifier][${trace}] vp_verify dur=${T.t_vp_verify_end - T.t_vp_verify_start}ms`);

    // Lookup session by state
    const session = [...verificationSessions.values()].find(s => s.state === state);
    if (!session) return res.status(400).json({ error: 'invalid_state' });

    // Nonce binding to the presentation
    if (vpPayload.nonce !== session.nonce) return res.status(400).json({ error: 'invalid_nonce' });

    // (OID4VP Presentation Submission) - check submission aligns with the request
    let submission = req.body.presentation_submission;
    if (typeof submission === 'string') {
      try { submission = JSON.parse(submission); } catch {}
    }
    if (submission && submission.definition_id &&
      submission.definition_id !== session.presentationDefinition.id) {
      return res.status(400).json({ error: 'invalid_presentation_submission' });
    }

    // Inspect VCs
    let userInfo = null;
    for (const vc of vpPayload.vp.verifiableCredential) {
      if (!vc) return res.status(400).json({ error: 'invalid_vc_null' });

      let vcPayload;
      if (typeof vc === 'string' && vc.includes('~')) {
        // SD-JWT VC
        const { payload, disclosedClaims } = await verifySdJwt(vc);
        vcPayload = payload;

        // disclosed claims into credentialSubject
        if (vcPayload?.vc?.credentialSubject) {
          vcPayload.vc.credentialSubject = {
            ...vcPayload.vc.credentialSubject,
            ...disclosedClaims
          };
          delete vcPayload.vc.credentialSubject._sd;
          delete vcPayload.vc.credentialSubject._sd_alg;
        }
      } else {
        // Plain JWT VC (legacy)
        const [encHeader, encPayload] = vc.split('.');
        const vcHeader = JSON.parse(base64url.decode(encHeader));
        vcPayload = JSON.parse(base64url.decode(encPayload));

        if (!vcHeader.kid) throw new Error('Missing kid in VC header');

        // Prefer issuer JWKS, fallback to registry
        const iss = vcPayload.iss;
        let issuerJwk;
        try {
          const jwksRes = await axios.get(`${iss}/.well-known/jwks.json`);
          issuerJwk = (jwksRes.data.keys || []).find(k => k.kid === vcHeader.kid);
        } catch {}
        if (!issuerJwk) {
          const reg = await axios.get(`${KEY_REGISTRY_URL}/.well-known/jwks.json`);
          issuerJwk = (reg.data.keys || []).find(k => k.kid === vcHeader.kid);
        }
        if (!issuerJwk) throw new Error(`Issuer key not found for kid ${vcHeader.kid}`);
        const issuerPubKey = await importJWK(issuerJwk, vcHeader.alg || 'ES256');
        await jwtVerify(vc, issuerPubKey);
      }

      T.t_vc_verify_start = now();
      
      // Holder binding (cnf.jwk must match VP header jwk)
      if (vcPayload?.cnf?.jwk) {
        const vpThumb = await calculateJwkThumbprint(protectedHeader.jwk);
        const vcThumb = await calculateJwkThumbprint(vcPayload.cnf.jwk);
        if (vpThumb !== vcThumb) throw new Error('holder_binding_failed');
      }
      
      T.t_vc_verify_end = now();
      console.log(`[timing][verifier][${trace}] vc_verify dur=${T.t_vc_verify_end - T.t_vc_verify_start}ms`);

      // REVOCATION UPDATES
      const nowz = Math.floor(Date.now() / 1000);

      // 1. Expiration check
      if (vcPayload.exp && vcPayload.exp < nowz) {
        console.warn('Credential expired:', vcPayload.jti);
        throw new Error('expired_credential');
      }

      // 2. Revocation check
      
      T.t_revoc_check_start = now();
      
      if (vcPayload.jti) {
        try {
          const statusUrl =
            vcPayload?.vc?.credentialStatus?.id ||
            `${vcPayload.iss}/.well-known/credential-status.json`;

          const resp = await axios.get(statusUrl, { timeout: 3000 });
          const revoked = resp.data.revoked || [];
          if (revoked.includes(vcPayload.jti)) {
            console.warn('Credential revoked:', vcPayload.jti);
            throw new Error('revoked_credential');
          }
        } catch (err) {
          console.error('Revocation check failed:', err.message);
          throw new Error('revocation_check_failed');
        }
      }
      
      T.t_revoc_check_end = now();
      console.log(`[timing][verifier][${trace}] revoc_check dur=${T.t_revoc_check_end - T.t_revoc_check_start}ms`);
      // REVOCATION UPDATES END
      
      
      userInfo = vcPayload?.vc?.credentialSubject;
      break;
    }
    
    const REQUIRED_CLAIMS = new Set(['studentId','enrollmentStatus']);

    if (!userInfo) return res.status(400).json({ error: 'no_valid_vc' });

    // studentId + enrollmentStatus
    const isMissing = (v) => (v === undefined || v === null || v === '');
    const missing = [...REQUIRED_CLAIMS].filter(name => isMissing(userInfo[name]));

    console.log('[verifier] userInfo (merged):', userInfo);
    console.log('[verifier] missing required:', missing);
    
    const miss = [...REQUIRED_CLAIMS].filter(n => {
      const v = userInfo[n]; return v === undefined || v === null || v === '';
    });
    if (miss.length) {
      return res.status(400).json({
        error: 'missing_required_fields',
        missing_fields: missing,
        message: `Access denied: ${miss.join(', ')} must be disclosed.`
      });
    }

    // Success -> create short-lived classroom session
    const sessionToken = `classroom_${crypto.randomBytes(16).toString('hex')}`;
    classroomSessions.set(sessionToken, {
      userId: userInfo.studentId,
      userName: userInfo.fullName,
      expiresAt: Date.now() + 15 * 60 * 1000
    });
    session.status = 'verified';
    
    console.log(`[timing][verifier][${trace}] verified_out total=${now() - T.t_cb_recv}ms`);

    return res.json({
      status: 'verified',
      redirect_url: `${CLASSROOM_BASE_URL}/session?token=${sessionToken}`,
      user_info: userInfo
    });
  } catch (err) {
    console.error('Verification failed:', err);
    return res.status(400).json({ error: 'verification_failed', message: err.message });
  }
});

// classroom session endpoint - sd-jwt
app.get('/session', (req, res) => {
  const token = req.query.token;
  const session = classroomSessions.get(token);
  
  if (!session) {
    return res.status(404).send('Invalid session token');
  }
  
  // Handle cases where selective disclosure might not include all user info
  const displayName = session.userName || `Student ${session.userId}`;
  const displayId = session.userId || 'Unknown';
  
  
  
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virtual Classroom Access</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            color: white; 
            font-family: 'Segoe UI', sans-serif;
            overflow: hidden;
        }
        #container {
            position: relative;
            width: 100vw;
            height: 100vh;
        }
        #countdown {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 8em;
            font-weight: bold;
            color: #4cc9f0;
            text-shadow: 0 0 20px rgba(76, 201, 240, 0.7);
            z-index: 100;
        }
        #message {
            position: absolute;
            top: 30%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 2em;
            text-align: center;
            color: white;
            z-index: 100;
        }
        #userInfo {
            position: absolute;
            bottom: 20%;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.2em;
            text-align: center;
            color: rgba(255, 255, 255, 0.8);
            z-index: 100;
        }
    </style>
</head>
<body>
    <div id="container">
        <div id="message">VR Classroom Access Granted</div>
        <div id="countdown">10</div>
        <div id="userInfo">Welcome, ${session.userName || 'Student'}! Session: ${token}</div>
        <canvas id="scene"></canvas>
    </div>

    <script>
        // Three.js Spiral with Looping Countdown
        const scene = new THREE.Scene();
        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        const renderer = new THREE.WebGLRenderer({ canvas: document.getElementById('scene'), antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setClearColor(0x000000, 0);

        // Create spiral
        function createSpiral(count = 500) {
            const points = [];
            const goldenAngle = Math.PI * (3 - Math.sqrt(5));
            
            for (let i = 0; i < count; i++) {
                const t = i / count;
                const radius = Math.sqrt(t) * 8;
                const angle = i * goldenAngle;
                
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);
                const z = (t - 0.5) * 15;
                
                points.push(new THREE.Vector3(x, y, z));
            }
            
            const geometry = new THREE.BufferGeometry().setFromPoints(points);
            const material = new THREE.PointsMaterial({
                color: 0x4cc9f0,
                size: 0.08,
                transparent: true,
                opacity: 0.8,
                sizeAttenuation: true
            });
            
            return new THREE.Points(geometry, material);
        }

        const spiral = createSpiral();
        scene.add(spiral);

        // Add orbiting spheres
        const sphereGeometry = new THREE.SphereGeometry(0.3, 16, 16);
        const sphereMaterial = new THREE.MeshBasicMaterial({ 
            color: 0xf72585,
            transparent: true,
            opacity: 0.6
        });
        
        const orbitingSpheres = [];
        for (let i = 0; i < 8; i++) {
            const sphere = new THREE.Mesh(sphereGeometry, sphereMaterial);
            scene.add(sphere);
            orbitingSpheres.push({
                mesh: sphere,
                radius: 3 + i * 0.5,
                speed: 0.02 + i * 0.005,
                angle: i * Math.PI / 4
            });
        }

        camera.position.z = 20;

        // Countdown logic with looping
        let count = 10;
        let countdownInterval;
        const countdownElement = document.getElementById('countdown');

        function startCountdown() {
            clearInterval(countdownInterval);
            countdownInterval = setInterval(updateCountdown, 1000);
        }

        function updateCountdown() {
            count--;
            countdownElement.textContent = count;
            countdownElement.style.color = count <= 3 ? '#f72585' : '#4cc9f0';
            
            if (count <= 0) {
                count = 10; // Reset countdown
                countdownElement.textContent = '10';
                countdownElement.style.color = '#4cc9f0';
            }
        }

        // Animation loop
        function animate() {
            requestAnimationFrame(animate);
            
            // Rotate spiral
            spiral.rotation.y += 0.01;
            spiral.rotation.x += 0.005;
            
            // Animate orbiting spheres
            orbitingSpheres.forEach((sphere, index) => {
                sphere.angle += sphere.speed;
                sphere.mesh.position.x = Math.cos(sphere.angle) * sphere.radius;
                sphere.mesh.position.z = Math.sin(sphere.angle) * sphere.radius;
                sphere.mesh.position.y = Math.sin(sphere.angle * 2) * 2;
            });
            
            renderer.render(scene, camera);
        }

        // Start everything
        startCountdown();
        animate();

        // Handle window resize
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    </script>
</body>
</html>`);
});


// Start server
app.listen(port, () => {
  console.log(`Verifier running at ${VERIFIER_BASE_URL}`);
});