---
author: "Anthony Castañeda"
title: "Working with SAML"
date: "2026-01-11"
description: "Fun with DevTools"
tags: ["SSO"]
---
## Troubleshooting SAML Using Your Browser’s DevTools

Single Sign-On (SSO) with SAML can feel opaque when something goes wrong. Users see a vague error, identity providers log something cryptic, and service providers often just say “authentication failed.” Fortunately, your browser already has one of the most powerful SAML troubleshooting tools built in: **Developer Tools (DevTools)**.

This post walks through a practical, repeatable approach to debugging SAML flows using browser DevTools, focusing on Chrome (the concepts apply equally to Firefox, Edge, and Safari).

---

## A Quick Refresher: How SAML Works

Before debugging, it helps to align on the basic SAML flow:

1. **User accesses the Service Provider (SP)**
2. SP redirects the browser to the **Identity Provider (IdP)** with a `SAMLRequest`
3. User authenticates at the IdP
4. IdP POSTs a `SAMLResponse` back to the SP
5. SP validates the response and logs the user in

Every one of these steps passes through the browser, which means DevTools can see it.

---

## Step 1: Open DevTools and Preserve the Trail

1. Open your browser’s DevTools (`Cmd+Option+I` on macOS, `Ctrl+Shift+I` on Windows)
2. Go to the **Network** tab
3. Enable:

   * ✅ **Preserve log** (critical—SAML involves redirects)
   * ✅ **Disable cache** (optional but helpful)

Now reproduce the login issue from the start.

---

## Step 2: Identify the SAML Requests

In the Network tab, filter using:

* `SAML`
* `login`
* `acs`
* `SSO`

You are typically looking for:

* A **redirect (302)** to the IdP containing a `SAMLRequest`
* A **POST** back to the SP containing a `SAMLResponse`

Click on each request and inspect it closely.

---

## Step 3: Inspect the SAMLRequest (SP → IdP)

Select the request that redirects to the IdP.

### Where to Look

* **Headers → Request URL**
* **Payload / Query Parameters**

You should see a `SAMLRequest` parameter. This is usually:

* Base64-encoded
* Often DEFLATE-compressed

### What to Check

* **Destination URL**: Is the browser being sent to the correct IdP endpoint?
* **RelayState**: Is it present and reasonable?
* **Binding**: Redirect binding vs POST binding (mismatch can break flows)

If the redirect never happens, the issue is almost certainly on the SP side.

---

## Step 4: Decode and Inspect the SAMLResponse (IdP → SP)

This is where most SAML problems live.

### Find the Response

Look for a **POST** request to your Assertion Consumer Service (ACS) URL. In DevTools:

* Method: `POST`
* Content-Type: `application/x-www-form-urlencoded`
* Parameter: `SAMLResponse`

### Decode the Response

1. Copy the `SAMLResponse` value
2. Base64-decode it (many online tools work, or use `base64 --decode`)
3. Open the resulting XML

### What to Validate in the XML

Check these elements carefully:

* `<Issuer>` – Does it match the expected IdP entity ID?
* `<Audience>` – Does it match the SP entity ID exactly?
* `<Recipient>` – Matches the ACS URL?
* `<InResponseTo>` – Matches the original request ID?
* `<Conditions NotBefore / NotOnOrAfter>` – Is clock skew causing expiration?
* `<NameID>` – Correct format and value?
* `<AttributeStatement>` – Are required attributes present?

A single character mismatch can cause validation failure.

---

## Step 5: Look for Signature and Certificate Issues

Still in the decoded XML:

* Is the assertion or response **signed**?
* Which element is signed (Assertion vs Response)?
* Does the certificate match what the SP is configured to trust?

Common failures include:

* Expired IdP certificate
* Signing the wrong element
* Algorithm mismatches (SHA-1 vs SHA-256)

If the SP logs say “invalid signature,” DevTools plus the decoded XML usually reveal why.

---

## Step 6: Use the Console for Silent Failures

Sometimes the network looks fine, but the browser still errors.

Check the **Console** tab for:

* CORS errors
* Mixed content (HTTP vs HTTPS)
* Cookie issues (`SameSite=None; Secure` is a frequent culprit)

Modern browser cookie policies can break otherwise correct SAML flows.

---

## Step 7: Compare a Working vs Broken Flow

One of the most effective techniques:

1. Capture a **working** SAML login in DevTools
2. Capture the **broken** one
3. Compare:

   * Endpoints
   * Parameters
   * Decoded XML

Differences usually jump out quickly.

---

## Common SAML Issues You Can Spot with DevTools

* ❌ Wrong ACS URL
* ❌ Incorrect entity ID
* ❌ Missing or malformed attributes
* ❌ Clock skew / expired assertions
* ❌ Certificate rotation not updated
* ❌ Cookie `SameSite` misconfiguration

All of these are visible from the browser.

---

## Final Thoughts

SAML may feel like “black box” authentication, but it isn’t. Because SAML relies on browser redirects and POSTs, **DevTools gives you near-complete visibility into the flow**.

If you can:

* Capture the network traffic
* Decode the assertions
* Read the XML carefully

You can debug most SAML issues without guessing—or waiting days on another team.

Once you get comfortable with DevTools, SAML troubleshooting becomes less of a mystery and more of a checklist.

Happy debugging 🔍
