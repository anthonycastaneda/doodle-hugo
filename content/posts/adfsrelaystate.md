---
author: "Anthony Castañeda"
title: "ADFS RelayState"
date: "2026-01-24"
tags: ["blog","adfs","auth-nerd"]
---

Do you have a weird request for an ADFS RelayState?  Read on and be illuminated.

---

## What is an ADFS Relay State?

**Relay State** is a piece of data passed through an SAML authentication flow that tells **ADFS** *where the user should end up after they successfully sign in*.

Think of it as a **return address**.

### In plain English

1. A user tries to access a protected app or deep link
2. They get redirected to ADFS to log in
3. ADFS authenticates the user
4. **Relay State tells ADFS where to send the user back to**

Without Relay State, users usually land on a default page instead of the exact resource they originally requested.

---

## Where Relay State Fits in the SAML Flow

High-level flow:

```shell
User → Service Provider (App)
     → ADFS (with RelayState)
     → ADFS authenticates user
     → Service Provider (SAML Response + RelayState)
```

Relay State is:

* Created by the **Service Provider (SP)** or client
* Passed **unchanged** through ADFS
* Returned to the SP after authentication

ADFS **does not interpret** Relay State—it just preserves and forwards it.

---

## What Can a Relay State Be?

Relay State is just a string, but in practice it’s commonly:

* A **URL** (most common)
* A **path** or route (`/orders/123`)
* A **base64-encoded value**
* An **opaque token** (looked up by the app later)

### Important limits

* In SAML 2.0, RelayState is typically limited to **~80 bytes** by spec
* ADFS itself is tolerant, but proxies and apps may not be

---

## How to Create a Relay State (Common Methods)

### Simple URL Relay State (Most Common)

When redirecting to ADFS, include RelayState as a query or POST parameter.

**Example (conceptual):**

```shell
RelayState=https://app.example.com/dashboard
```

After login, the user lands back on `/dashboard`.

✅ Simple
⚠️ Must validate the URL to avoid open redirect attacks

---

### Deep-Link Relay State

Used when a user bookmarks or directly accesses a protected resource.

```shell
RelayState=https://app.example.com/orders/84721
```

After authentication:

* User is returned to the **exact page** they wanted

---

### Encoded or Tokenized Relay State (Best Practice)

Instead of passing a raw URL:

```shell
RelayState=abc123xyz
```

Your app then:

1. Receives `abc123xyz`
2. Looks it up server-side
3. Redirects the user safely

✅ Safer
✅ Avoids length limits
✅ Prevents URL tampering

---

### Relay State in an IdP-Initiated Flow

ADFS can initiate login (no SP request first).

In this case:

* Relay State is configured **inside ADFS**
* Often tied to a **Relying Party Trust**
* Used to select the landing page or app context

This is common for:

* Portals
* App launch pages
* Tiles in ADFS access pages

---

## How to Configure or Use Relay State with ADFS

### From the Application (SP side)

* Include `RelayState` in the SAML AuthnRequest
* Expect it back **unchanged** with the SAML response
* Handle it securely after validation

### From the ADFS side

* ADFS does **not generate** Relay State automatically
* It only:

  * Accepts it
  * Stores it temporarily
  * Returns it

For IdP-initiated sign-on:

* Configure default or fixed Relay State in the Relying Party Trust settings

---

## Security Considerations (Very Important)

Never blindly redirect based on Relay State.

Always:

* Validate allowed domains
* Use allowlists
* Prefer opaque tokens over raw URLs
* Reject unexpected or malformed values

Relay State is a **common attack vector** for open redirects if handled carelessly.

---

## When You Actually Need Relay State

You almost certainly need it if:

* Users deep-link into your app
* You want a smooth login experience
* You support multiple entry points
* You don’t want users dumped on a generic home page

---

## Javascript example

```javascript
/**
 * Minimal SAML 2.0 AuthnRequest generator (SP-initiated) for ADFS using
 * HTTP-Redirect binding:  SAMLRequest = base64(deflateRaw(xml))
 *
 * Includes an example RelayState you would send alongside SAMLRequest.
 *
 * NOTE:
 * - You typically do NOT sign the AuthnRequest for ADFS unless your setup requires it.
 * - This example focuses on generating the XML + Redirect-binding encoding.
 */

import crypto from "crypto";
import { deflateRaw } from "pako"; // npm i pako

function samlTimestamp(date = new Date()) {
  // e.g. 2026-01-24T13:45:12Z
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function generateId() {
  // SAML IDs often look like _<random>
  return "_" + crypto.randomBytes(20).toString("hex");
}

/**
 * Create an AuthnRequest XML string.
 *
 * @param {object} opts
 * @param {string} opts.issuer           SP EntityID (your app)
 * @param {string} opts.destination      ADFS SSO endpoint, e.g. https://adfs.example.com/adfs/ls/
 * @param {string} opts.acsUrl           Your Assertion Consumer Service URL
 * @param {string} [opts.nameIdFormat]   Optional NameIDPolicy format
 * @param {boolean} [opts.forceAuthn]    Optional ForceAuthn
 * @param {boolean} [opts.passive]       Optional IsPassive
 */
export function buildAuthnRequestXml(opts) {
  const id = generateId();
  const issueInstant = samlTimestamp();

  const {
    issuer,
    destination,
    acsUrl,
    nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    forceAuthn = false,
    passive = false,
  } = opts;

  // Minimal AuthnRequest. You can add RequestedAuthnContext, Scoping, etc. if needed.
  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
    `ID="${id}" Version="2.0" IssueInstant="${issueInstant}" ` +
    `Destination="${destination}" ` +
    `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ` +
    `AssertionConsumerServiceURL="${acsUrl}" ` +
    `ForceAuthn="${forceAuthn ? "true" : "false"}" ` +
    `IsPassive="${passive ? "true" : "false"}">` +
    `<saml:Issuer>${escapeXml(issuer)}</saml:Issuer>` +
    `<samlp:NameIDPolicy Format="${escapeXml(nameIdFormat)}" AllowCreate="true" />` +
    `</samlp:AuthnRequest>`;

  return { id, issueInstant, xml };
}

/**
 * Encode XML into SAMLRequest for HTTP-Redirect binding:
 * deflateRaw -> base64 -> urlEncode
 */
export function encodeSamlRequestForRedirect(xml) {
  const deflated = deflateRaw(xml); // Uint8Array
  const base64 = Buffer.from(deflated).toString("base64");
  const urlEncoded = encodeURIComponent(base64);
  return { base64, urlEncoded };
}

/**
 * Build the final ADFS redirect URL including SAMLRequest and RelayState.
 *
 * @param {object} opts
 * @param {string} opts.adfsSsoUrl   e.g. https://adfs.example.com/adfs/ls/
 * @param {string} opts.samlRequest  URL-encoded SAMLRequest
 * @param {string} opts.relayState   Any opaque string (keep it short; many stacks expect <= ~80 bytes)
 */
export function buildAdfsRedirectUrl({ adfsSsoUrl, samlRequest, relayState }) {
  const sep = adfsSsoUrl.includes("?") ? "&" : "?";
  const relay = encodeURIComponent(relayState);
  return `${adfsSsoUrl}${sep}SAMLRequest=${samlRequest}&RelayState=${relay}`;
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

// ----------------------
// Example usage
// ----------------------
const issuer = "https://sp.example.com/saml/metadata"; // SP entityID
const adfsSsoUrl = "https://adfs.example.com/adfs/ls/"; // ADFS SSO endpoint (IdP)
const acsUrl = "https://sp.example.com/saml/acs"; // SP ACS endpoint
const relayState = "/app/orders/84721"; // what you want to restore after login (often a path or token)

const { xml } = buildAuthnRequestXml({
  issuer,
  destination: adfsSsoUrl,
  acsUrl,
});

const { urlEncoded } = encodeSamlRequestForRedirect(xml);

const redirectUrl = buildAdfsRedirectUrl({
  adfsSsoUrl,
  samlRequest: urlEncoded,
  relayState,
});

console.log("AuthnRequest XML:", xml);
console.log("Redirect URL:", redirectUrl);

/**
 * In a web app, you'd do:
 *   res.redirect(redirectUrl);
 */
```
