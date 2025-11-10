# IMMERSE Wallet & Credential Ecosystem UI Documentation

## Table of Contents

- [IMMERSE Wallet \& Credential Ecosystem UI Documentation](#immerse-wallet--credential-ecosystem-ui-documentation)
- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Architecture](#architecture)
- [Wallet Interface](#wallet-interface)
- [Issuer Interface](#issuer-interface)
- [Verifier Interface](#verifier-interface)
- [Virtual Classroom](#virtual-classroom)
- [Technical Implementation](#technical-implementation)
- [Device Compatibility \& Testing](#device-compatibility--testing)
- [Dependencies \& Libraries](#dependencies--libraries)
- [Setup \& Deployment](#setup--deployment)

## Overview

The IMMERSE Wallet ecosystem provides an identity and access management framework for immersive environments, using Verifiable Credentials (VCs) to ensure secure, privacy-preserving interactions across 2D, 3D, and AR interfaces. It enables secure issuance, storage, and verification of VCs through intuitive 2D, 3D, and Augmented Reality (AR) interfaces. The interface architecture comprises four interconnected components that aim to create an uninterrupted user experience from credential issuance to verified access.

The Wallet serves as a user agent, providing individuals with complete authority over their personal data and credentials, as well as with the ability to store and present their VCs. The Issuer component enables educational institutions to create and distribute VCs to students, while the Verifier component controls access to protected resources, such as virtual classrooms (in the context of the presented use case use case). Finally, the Virtual Classroom offers an immersive learning environment that becomes accessible only after successful credential verification.

One of the main principles of the design of the IMMERSE ecosystem is balancing interoperability and standards-based security, with a user experience that is suitable for immersive environments. By implementing open standards, such as OpenID for Verifiable Credentials (OID4VCI) and OpenID for Verifiable Presentations (OID4VP), the platform ensures interoperability, while presenting complex cryptographic operations through interfaces that are both intuitive and engaging for the end-user.

## Architecture

The IMMERSE Wallet ecosystem is built using standard web technologies, i.e. HTML, CSS, and JavaScript, ensuring broad compatibility across devices and platforms. For the immersive 3D and AR components, we have integrated Three.js, a powerful WebGL-based graphics library that enables high-performance rendering of complex scenes across different hardware configurations, along with the WebXR Device API for AR functionality.

Authentication relies on JSON Web Tokens (JWTs) and credential data conforms to the World Wide Web Consortium (W3C) VC data model. Support for Selective Disclosure JWT (SD-JWT) enables privacy-preserving credential sharing, ensuring that users can only disclose the necessary attributes for each interaction.

From a high-level perspective, we describe the use case through the interface as follows. The flow, as depicted in the demos, begins with user authentication through the Wallet interface (i.e. login page). Educational institutions issue credentials via deep links that integrate directly with the wallet. When users need to prove their qualifications or access rights, verifiers request Verifiable Presentations (VPs) through similar deep link mechanisms. The selective disclosure capability ensures users maintain control over their personal data, sharing only what's necessary. Successful verification finally grants access to the immersive virtual classroom environment.

When verification fails, which occurs when users do not disclose the necessary attributes requested by the IMMERSE Verifier, the user is informed through an advisory message highlighting which attributes should be disclosed. Note that a more comprehensive presentation of the use case is available in the Use Case doc.

## Wallet Interface

The Wallet interface enables the users to easily manage their VCs. It supports multiple interaction modes, 2D, 3D, and AR, to accommodate different preferences and device capabilities. The traditional 2D desktop mode provides a familiar card-based layout and is suitable for quick access to credential details. For users seeking a more engaging experience, the 3D preview mode presents credentials as floating objects in an immersive space where they can be inspected from all angles. The most advanced interface is the AR experience, which leverages WebXR to place credentials directly into the user's physical environment through AR.
Deep link support ensures that when users receive credential offers or verification requests through deep links, the Wallet automatically processes these requests and presents them through intuitive interfaces that guide users through the necessary actions.

*The login interface:*

```html
<div id="login-section" class="section active">
    <div class="form-group">
        <label class="form-label" for="username">Username</label>
        <input type="text" id="username" class="form-input" placeholder="Enter username">
    </div>
    <button id="do-login" class="btn btn-primary">Login</button>
</div>
```

Credential display follows a card-based design that presents essential information at a glance while providing detailed views on demand. Each credential card shows the credential type, issuer information, issuance date, and visual indicators for special capabilities, such as selective disclosure. The design uses color coding and icons to help users quickly identify different credential types and their status.

*Credential display:*
<img width="1750" height="734" alt="credential display" src="https://github.com/user-attachments/assets/5243b9bc-c0f2-4cff-b7cf-36d5ae912794" />


In the 3D preview mode, using Three.js, credentials are rendered as floating objects in a spacious virtual environment. Users can orbit around these objects, inspecting them from different angles, with a raycasting system enabling intuitive selection through mouse or touch interactions.

*Credential display in 3D preview mode:*
<img width="1404" height="889" alt="3d credential display" src="https://github.com/user-attachments/assets/9114d611-99d3-4071-9694-6b8305a43cd4" />


*3D scene in the IMMERSE Wallet:*

```javascript
function initPreviewMode() {
    const scene = new THREE.Scene();
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true });
    const camera = new THREE.PerspectiveCamera(75, canvas.clientWidth / canvas.clientHeight, 0.1, 1000);
    
    // Lighting setup
    scene.add(new THREE.AmbientLight(0xffffff, 0.55));
    const dir = new THREE.DirectionalLight(0xffffff, 0.9);
    dir.position.set(5, 5, 5);
    scene.add(dir);
}
```

The AR experience represents the most advanced interface mode, leveraging the WebXR API to create immersive interactions. In AR mode, credentials are visualized as floating 3D objects within the user's real-world view. Users can interact with the scene by moving, rotating, or selecting objects using standard XR gestures, through a touchpad or with controller input. The implementation includes gesture recognition compatible with the AR headset for rotating, scaling, and positioning credential objects, aiming to make the experience intuitive even for users new to AR.

*AR experience scene:*

Voice guidance is implemented through the Web Speech API's `SpeechSynthesisUtterance` interface, which dynamically selects the most appropriate voice available on each browser for consistent narration quality, with a text-to-speech system that provides context-aware instructions. The audio feedback system includes distinctive sound effects for different interactions, creating a multi-sensory experience that helps users understand system state without relying solely on visual cues.


## Issuer Interface

Through IMMERSE Issuer's interface users can obtain VCs (in the context of the presented use case from educational institutions). The system aims to support multiple credential types tailored to educational use cases, including student identification, course completion certificates, academic transcripts, and specialized achievement badges. Each credential type includes predefined claim structures that, if adopted by an educational institute, can be customized to meet specific institutional requirements.

Similarly to the IMMERSE Wallet, the IMMERSE Issuer interface allows students to preview how their credentials will appear across different viewing environments, i.e. modes. The 2D mode offers a familiar and comfortable user experince, while the 3D preview serves as a "simplified" AR experience and the AR mode allows the users to interact with the entity with the proper equipment. The deep link mechanism automatically creates secure, one-time-use URLs that direct students to credential offers within their wallets. These links incorporate appropriate security measures to prevent unauthorized access while maintaining a seamless user experience.

*modes.*
<img width="1499" height="852" alt="issuer 2d" src="https://github.com/user-attachments/assets/a0f5644b-eefb-44fe-912f-4bc264f90f44" />
<img width="952" height="716" alt="issuer 3d" src="https://github.com/user-attachments/assets/7656b237-9ffb-445c-bd4b-db1fce78678f" />


The responsive design of the IMMERSE Issuer ensures that students can access the Issuer interface effectively across all their devices, from desktop computers to mobile phones and tablets. This flexibility supports various credential issuance scenarios, whether students are accessing the portal from home, campus computer labs, or mobile devices during events.

## Verifier Interface

Through the OID4VP protocol, the IMMERSE Verifier validates users' VPs and confirms that required credential attributes are authentic and have not been tampered with. The system then grants access to protected resources, such as virtual classrooms, based on verified claims, while selective disclosure preserves user privacy.

The verification process begins when a user attempts to access a VR classroom through the IMMERSE Verifiers page. The system generates a presentation request specifying exactly which credential attributes are required for access (presentation definition). This request is delivered to the user's wallet through a deep link, initiating a secure verification flow.

When users receive verification requests, they see clear explanations of what information is being requested and why it's needed. The interface distinguishes between required claims, those necessary for access, and optional claims that might enhance the experience but aren't strictly necessary. This transparency helps users make informed decisions about what information to share.

When users hold credentials with selective disclosure capabilities, they can choose exactly which attributes to reveal from a larger set of available claims (this is part of the IMMERSE Wallet's interface). The (IMMERSE Wallet) interface clearly indicates which claims are required for access and which are optional, with visual cues helping users understand the implications of their disclosure choices.

```javascript
function showVerificationRequest(verificationData) {
    // Build requested names set from presentation definition
    const REQUIRED_CLAIMS = new Set(
        (verificationData.requested_fields || [])
        .map(f => f && f.name)
        .filter(Boolean)
    );
    
    // Present clear interface for selective disclosure
    renderDisclosureInterface(verificationData, REQUIRED_CLAIMS);
}
```

Successful verification triggers access to the protected resource, in this context the virtual classroom, with a smooth transition. The system includes appropriate error handling for failed verification attempts, with clear explanations that help users understand what went wrong and how to resolve the issue.

*modes.*
<img width="1462" height="832" alt="verifier 2d" src="https://github.com/user-attachments/assets/a63e0c9b-ce4f-4f0d-a9d4-884486f364d7" />
<img width="1244" height="878" alt="verifier 3d" src="https://github.com/user-attachments/assets/39b8ab45-4b4d-4435-b375-a626f90ada03" />


## Virtual Classroom

The Virtual Classroom serves as a placeholder for the use case and represents the destination environment that becomes accessible after successful VP verification. Upon successful verification, users enter a transitional space featuring a countdown timer and personalized (depending on the attributes they chose to disclose) welcome message. The countdown, set at 10 seconds, could ensure that all system components are properly initialized before the main experience begins. In this context, it simply provides a clear transition point between the verification process and the learning environment.

The visual design centers around a spiral visualization. It is rendered using Three.js. Should users chose to disclose their full name, personalization includes the interface displaying the verified user's name and relevant session information, creating immediate recognition and reinforcing the connection between identity verification and access. This helps users feel welcomed as individuals rather than anonymous participants. However, it is not necessary that the full name is disclosed, and an example of this is in the 2D demo. The particle systems that create the visual effects are carefully tuned to provide visual interest without overwhelming system resources. Orbiting spheres move in mathematically determined patterns around the central spiral, and their movements synchronized to create harmonious visuals.

Accessibility considerations are embedded throughout the virtual classroom design. The color schemes provide sufficient contrast for readability, and the interface supports the three aforementioned to accommodate different user preferences and abilities.

*Virtual Classroom scene.*
<img width="1268" height="888" alt="Screenshot 2025-11-10 163138" src="https://github.com/user-attachments/assets/829f856f-6fdc-433e-b486-14edc1b6a6c2" />


## Technical Implementation

The technical implementation of the IMMERSE Wallet ecosystem is built entirely on web standards, ensuring broad accessibility without requiring users to install specialized software or applications.

The audio-visual system plays a crucial role in creating an engaging, multi-sensory experience. Voice synthesis is implemented using the Web Speech API, providing spoken guidance and feedback throughout the interface. During testing, we evaluated the available system voices across different browsers and identified those that users found most natural; these were set as the preferred defaults. The application includes logic to automatically select the most suitable available voice to ensure a consistent listening experience across browsers and devices.

```javascript
function speak(text) {
    if (!audio.enabled) return;
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
```

Sound effects provide additional feedback for user interactions, with distinct audio signatures for different types of events. High-frequency "tick" sounds indicate selection and navigation actions, while "chime" sounds mark significant events, such as mode transitions or successful operations. The audio system properly manages the Web Audio API context, ensuring sounds play reliably while respecting browser autoplay policies.

The Three.js integration represents one of the most complex aspects of the technical implementation. The 3D rendering system manages multiple scenes with different characteristics optimized for their specific use cases. The 3D preview mode emphasizes visual quality and interactions, with detailed geometries, sophisticated materials, and animated meshes and pulsing emissive effects to mimic dynamic lighting and create an engaging environment. The AR mode prioritizes performance and stability, with optimized geometries and efficient rendering pipelines that maintain smooth frame rates even on mobile devices.

The responsive design system uses CSS custom properties (variables) to maintain consistent styling across different viewports and devices. This approach enables systematic adjustments to spacing, typography, and layout based on screen characteristics, ensuring optimal readability and usability regardless of how users access the system.

```css
:root {
    --primary: #4361ee;
    --secondary: #3a0ca3;
    --accent: #f72585;
    --light: #f8f9fa;
    --dark: #212529;
    --transition: all 0.3s ease;
}
```

The mobile experience also receives particular attention in the implementation, with touch-friendly interface elements, appropriately sized touch targets, and gestures that aim to feel natural on touchscreen devices. The system detects touch capabilities and adjusts interactions accordingly, for example, replacing hover effects with tap actions on touch devices.

Performance is considered throughout the implementation. The 3D preview and AR scenes use simplified materials and geometry appropriate to each mode, and the renderer caps its pixel ratio to prevent excessive rendering on high-resolution (high-DPI) displays. Animations are lightweight and avoid post-processing, helping maintain smooth frame rates on mobile hardware.

## Device Compatibility & Testing

The IMMERSE Wallet ecosystem has undergone extensive testing across a diverse range of devices and platforms to ensure consistent performance and user experience. Our testing methodology emphasizes real-world usage scenarios across the different interface modes we employ (2D, 3D, and AR) with particular attention to the unique requirements of each interaction paradigm.

Our primary AR testing has been conducted using the Samsung Galaxy S24 FE smartphone paired with the XREAL AIR 2 PRO augmented reality glasses. The combination provides adequate processing power for complex 3D rendering while maintaining smooth performance throughout extended usage sessions.

For iOS compatibility testing, we've utilized the iPhone 15 running the latest versions of iOS. As noted in our testing, Chrome on iOS does not support WebXR due to Apple's requirement that all browsers on iOS use the WebKit rendering engine. Since WebKit does not currently implement the WebXR API, this limitation affects all browsers on iOS regardless of their capabilities on other platforms. However, we've successfully launched AR functionality on iOS using Mozilla's WebXR Viewer application, available through the App Store. Interestingly, we observed that the wallet interface functions within the Safari browser, though the consistency of this experience varies (see below). The most reliable AR experience on iOS currently comes through the dedicated WebXR Viewer app rather than through standard mobile browsers. Note that there have been no tests that include the Vision Pro headset.

*iOS tests.*
*Issuer:*
![i2d1](https://github.com/user-attachments/assets/1c3da622-65f3-4886-95b1-f593eeff43c8)
![i2d2](https://github.com/user-attachments/assets/5b26e245-6569-482e-9509-cd249a12bf81)
![i2d3](https://github.com/user-attachments/assets/5a83df50-9fe9-43a2-8d14-bacf9866559d)
![i2d4](https://github.com/user-attachments/assets/d7933c43-61bc-4746-afe1-081ee349729c)
![i3d1](https://github.com/user-attachments/assets/b6b3b1d6-64d4-4359-964b-0eb136382694)
![i3d2](https://github.com/user-attachments/assets/836d9a3a-35ef-4c7e-be7a-8a95a2742a35)
![i3d3](https://github.com/user-attachments/assets/ae9efcdd-6628-4389-a71c-e2f5a143557d)
![iar1](https://github.com/user-attachments/assets/d6f2c323-cabc-43a1-a953-f88813a7cdd8)


Looking toward the future, Apple's announcement of WebXR support for the Vision Pro headset suggests that broader WebXR adoption may be coming to Apple's ecosystem. This development could significantly improve AR accessibility for iOS users in the coming years, potentially eliminating the need for dedicated WebXR applications.

For Android devices without dedicated AR glasses, the system still provides a functional AR experience using the device's screen and sensors. In WebXR-compatible browsers, such as Chrome on ARCore-supported phones, the browser provides camera passthrough and six-degrees-of-freedom (6-DoF) motion tracking (i.e. the AR system tracks both where the user is and which way she's facing, enabling the virtual objects to stay correctly oriented and positioned as she moves around), while the transparent Three.js renderer (`alpha: true`) overlays the virtual scene on top of the live camera feed. While this "magic window" approach doesn't offer the same level of immersion as dedicated AR glasses, it does allow users to position and interact with credential objects in their physical environment. The rendering quality in this mode remains high, though the experience naturally feels more like looking through a portal into an AR world rather than having objects seamlessly integrated into the user's environment. Android testing was primarily conducted on Samsung Galaxy A15, Samsung Galaxy A16, Samsung Galaxy A80, CUBOT X20 Pro, and Xiaomi Redmi 15C, with comparable results observed on Motorola G54, Realme Narzo 60x, and OnePlus Nord CE 3 Lite, all representative of mid-range devices capable of running WebXR through Chrome with consistent frame rates and smooth rendering.

*Android tests.*

Our testing has also included various desktop configurations for the 2D and 3D preview modes, with consistent performance across modern browsers including Chrome, Firefox and Edge. The 3D preview mode works particularly well on desktop systems with dedicated graphics cards, though even integrated graphics solutions provide acceptable performance for the relatively lightweight scenes used in credential visualization.

## Dependencies & Libraries

The IMMERSE Wallet ecosystem utilizes the following libraries and dependencies.

Three.js serves as the foundation of our 3D and AR rendering capabilities. It provides a comprehensive set of tools for creating and manipulating 3D scenes in the browser. We specifically use version r128, which represents a stable release with proven performance characteristics and broad device support. The library's WebGL renderer forms the basis of both our 3D preview scenes and our AR experiences, ensuring consistent rendering quality across different interaction modes.

```javascript
// Three.js scene initialization for AR
const renderer = new THREE.WebGLRenderer({
    canvas,
    antialias: true,
    alpha: true,
    preserveDrawingBuffer: false,
    powerPreference: 'high-performance'
});
renderer.xr.enabled = true;
renderer.xr.setReferenceSpaceType('local-floor');
```

Font Awesome provides our icon system. Specifically, we utilize version 6.4.0, which includes both classic and modern icon styles that align with our interface aesthetic. The icon library helps users quickly identify functions and understand interface elements without relying solely on text labels.

The OrbitControls extension for Three.js enables intuitive camera manipulation in our 3D preview mode. This well-established control scheme allows users to orbit around scenes, zoom in for closer inspection, and pan to examine content from different angles. The controls include damping and inertia for smooth, natural-feeling interactions that make the 3D environment feel responsive and polished.

For AR functionality, we rely on the WebXR Device API, a W3C standard that enables immersive experiences on the web. This API provides the foundation for accessing AR capabilities across compatible devices and browsers, with a consistent programming model that works across different hardware platforms. Our implementation specifically uses the 'immersive-ar' session type with 'local-floor' reference spaces, which align well with our use case of placing credential objects in the user's environment.

The Web Audio API enables our sound effects and audio feedback system, providing low-latency audio processing that ensures sounds play at precisely the right moments during user interactions. For voice synthesis, we utilize the Web Speech API's SpeechSynthesis interface, which provides text-to-speech capabilities without requiring external services or libraries.

Our credential handling implements the OpenID for Verifiable Credentials Issuance (OID4VCI) and OpenID for Verifiable Presentations (OID4VP) specifications, which represent the current industry standards for VC exchange. These standards ensure interoperability with other compliant systems, while providing robust security guarantees through well-defined protocol flows.

For selective disclosure capabilities, we implement the Selective Disclosure for JWTs (SD-JWT) specification, which enables privacy-preserving credential presentations, where users can reveal only specific claims included in their credentials. This approach ensures user privacy, while maintaining the verifiability of presented information.

## Setup & Deployment

The main requirement is a modern web browser with WebGL support, which includes virtually all current browsers on both desktop and mobile platforms. For the full AR experience, browsers must also support the WebXR API, which currently includes Chrome and Firefox on Android, and in desktop Chrome and Edge for VR-capable systems. As discussed in the compatibility section, iOS requires the dedicated WebXR Viewer application for AR functionality due to platform restrictions.

A critical requirement for production deployment is HTTPS configuration. The WebXR API requires secure contexts for AR functionality, meaning services must be served over HTTPS rather than HTTP. This requirement aligns with security best practices for web applications handling sensitive identity information. Additionally, many browser features, including certain audio APIs, exhibit different behavior in secure contexts versus insecure ones.

The backend API integration represents a crucial configuration step. The frontend code contains configuration points for API endpoints that handle credential operations, authentication, and verification processes. These endpoints must be implemented according to the OID4VCI and OID4VP specifications to ensure proper interoperability with the wallet interface.

```javascript
// Backend API configuration in frontend code
const state = {
    sessionToken: localStorage.getItem('sessionToken') || null,
    credentials: [],
    verificationRequests: [],
    currentVerification: null,
    backendUrl: '/api', // Update to actual backend URL
    selectivePresentations: {}
};
```

For development and testing purposes, the system can be run on localhost (e.g., with self-signed certificates) or made accessible through tunneling services, such as ngrok. This repository includes shell scripts (.sh) that automate these setup steps for convenience and simplicity for development purposes. However, these methods are intended solely for local development and are not suitable for production deployment. Production environments require proper SSL certificate configuration and domain setup to ensure secure operation and full WebXR functionality.

Browser compatibility testing should cover the specific browsers and devices used by the target user base. While the system works across modern browsers, certain features, particularly around AR and audio, may exhibit subtle differences that may require potential adjustment on the user's end for specific environments. For example, we observed an issue with sound playback on the Samsung Galaxy A80 when the "sound on" button was pressed. It's unclear whether this was due to the device itself, the user's configuration, or another factor, as the feature worked consistently across all other tested devices.

Ongoing maintenance should include monitoring for updates to the underlying libraries and web standards.

## **References**

- **Three.js** - *JavaScript 3D library.* Available at: [https://threejs.org](https://threejs.org) (MIT License)
- **OrbitControls (Three.js examples)** - Part of the Three.js examples module. Available at: [https://threejs.org/docs/#examples/en/controls/OrbitControls](https://threejs.org/docs/#examples/en/controls/OrbitControls) (MIT License)
- **WebGL** - *Web Graphics Library.* Khronos Group. Specification: [https://www.khronos.org/webgl/](https://www.khronos.org/webgl/)
- **WebXR Device API** - W3C Immersive Web Working Group. Candidate Recommendation. [https://immersive-web.github.io/webxr/](https://immersive-web.github.io/webxr/)
- **Web Audio API** - W3C Audio Working Group. Specification: [https://www.w3.org/TR/webaudio/](https://www.w3.org/TR/webaudio/)
- **Web Speech API** - W3C Community Draft. [https://wicg.github.io/speech-api/](https://wicg.github.io/speech-api/)
- **Font Awesome 6.4.0** - Icon library for scalable vector icons. [https://fontawesome.com/](https://fontawesome.com/) (MIT License)
- **Selective Disclosure JWT (SD-JWT)** - Fett, D. et al. *IETF Draft: OAuth Selective Disclosure JWT.* [https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
- **W3C Verifiable Credentials Data Model 2.0** - World Wide Web Consortium Recommendation. [https://www.w3.org/TR/vc-data-model-2.0/](https://www.w3.org/TR/vc-data-model-2.0/)
- **OpenID for Verifiable Credential Issuance (OID4VCI)** - OpenID Foundation / IETF OAuth WG Draft. [https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html)
- **OpenID for Verifiable Presentations (OID4VP)** - OpenID Foundation / IETF OAuth WG Draft. [https://openid.net/specs/openid-4-verifiable-presentations-1_0.html](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- **Mozilla WebXR Viewer** - Experimental WebXR browser for iOS. Mozilla Mixed Reality Team. [https://apps.apple.com/us/app/webxr-viewer/id1295998056](https://apps.apple.com/us/app/webxr-viewer/id1295998056)
