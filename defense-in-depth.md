# Defense-in-Depth for a private cloud behind Cloudflare (mTLS → OTP → App MFA)

> **Goal:** Rationale and guidance for a multi-layer Zero-Trust design: **mTLS** (device factor) **+** **OTP/Access** (edge login) **+** **Cloud MFA** (application factor) — each on a distinct layer with clear operational policies.

---

## Table of Contents
- [Why mTLS **and** OTP **and** App MFA?](#why-mtls-and-otp-and-app-mfa)
- [Layer Mapping (OSI & Defense-in-Depth)](#layer-mapping-osi--defense-in-depth)
- [Threat Model (brief)](#threat-model-brief)
- [Edge Policies (Cloudflare) — Best Practices](#edge-policies-cloudflare--best-practices)
- [Origin Hardening (Nginx/Cloud)](#origin-hardening-nginxcloud)
- [Operations & Forensics](#operations--forensics)
- [Minimal Checklist](#minimal-checklist)

---

## Why mTLS **and** OTP **and** App MFA?

1. **Separate proofs per layer (Zero Trust):**  
   - **mTLS** = *device possession* at transport (client cert in local keystore).  
   - **OTP/Access** = *user login* at the edge (time-bound session).  
   - **Cloud MFA** = *second user factor* inside the app (TOTP/WebAuthn).  
   → An attacker needs **device + user + app access**.

2. **Phishing/session resilience:**  
   - A stolen OTP is **useless** without the client certificate (mTLS).  
   - Even with an edge session, **app MFA** remains an independent barrier.

3. **Smaller blast radius & independent rotation:**  
   - Device compromise → **revoke cert**, accounts remain intact.  
   - Account compromise → rotate **MFA/creds**, device gating remains separate.

4. **Egress-only & edge cost control:**  
   - **Egress-only tunnel** shields the origin; **Access** enforces policies and session limits **before** origin resources are touched.

---

## Layer Mapping (OSI & Defense-in-Depth)

| Layer | Control | Purpose |
|---|---|---|
| **Network/Transport (L4–6)** | **mTLS (client certificate)** | Enforce device identity; block unknown devices **before** any login |
| **Edge Identity** | **Cloudflare Access (OTP/IdP, session, binding cookie)** | User identity & session policy, pre-origin |
| **Reverse-Proxy Boundary** | **Nginx (TLS, HSTS/headers, IP ACLs, limits/timeouts, URI normalization)** | Policy chokepoint, safe hand-off to app |
| **Application (L7)** | **Cloud MFA + app auth** | Account protection even if edge session is abused |
| **Backends** | **Private networks (Docker), no public ports** | Micro-segmentation, minimal attack surface |

---

## Threat Model (brief)

- **Phished OTP** → blocked by **mTLS** (*edge 403, no login page*).  
- **Stolen/lost device** → **app MFA** still required; **revoke** the cert.  
- **Edge session hijack** → **app MFA** stops account takeover.  
- **Untrusted host/network** → **edge policies** (mTLS required, optional issuer/serial allowlist, binding cookie) block early.  
- **Origin exposure** → **egress-only** tunnel + reverse-proxy boundary; no direct inbound exposure.

---

## Edge Policies (Cloudflare) — Best Practices

- **Enforce mTLS** for `cloud.example.com` (SSL/TLS → Client Certificates → *Require*).  
- **Access app (Self-hosted):** OTP/IdP, moderate session lifetime, **binding cookie** enabled.  
- **Optional allowlist** via WAF (issuer + serial, *in addition* to `cert_verified`):  
  ```txt
  (http.host eq "cloud.example.com"
    and not (
      cf.tls_client_auth.cert_verified
      and lower(cf.tls_client_auth.cert_issuer_dn) contains "your client ca name"
      and lower(cf.tls_client_auth.cert_serial) in {"<serial_lowercase_no_colons>"}
    )
  )
  ```
- **Separate paths:** `sync.example.com` (app bypass/policy), `share.example.com` (public/mild).  
- **Egress-only tunnel:** no inbound ports; `cloudflared` talks to **127.0.0.1**/**LAN** at the origin.

---

## Origin Hardening (Nginx/Cloud)

- **Nginx as reverse-proxy boundary:** TLS, HSTS/headers, **IP ACLs**, **limits/timeouts**, **URI normalization**.  
- **Docker micro-segmentation:** private bridges (e.g., `nc-net`), **no** published ports for Redis/DB/ ...  
- **Cloud trust anchors:**  
  - `trusted_domains`: `cloud.example.com`, `sync.example.com`, LAN/ports.  
  - `trusted_proxies`: Nginx IP + `127.0.0.1`.  
  - `forwarded_for_headers`: `HTTP_CF_CONNECTING_IP`, `HTTP_X_FORWARDED_FOR`.  
  - `overwriteprotocol=https`.  
- **Firewall (iptables/DOCKER-USER):** allow loopback/LAN, **DROP** everything else (fail-closed).

---

## Operations & Forensics

- **Cert hygiene:** short lifetimes, clear device names, **revoke** process.  
- **Independent rotation:** device certs vs. app MFA managed separately.  
- **Monitoring:** Cloudflare **Logs** (mTLS/Access), `cloudflared` status, Nginx/Cloud logs.  
- **Safe rollback:** adjust WAF/Access policy; stop tunnel if needed; origin stays non-exposed.

---

## Minimal Checklist

- [ ] **mTLS** required on `cloud.example.com` (`cert_verified`).  
- [ ] **Access (OTP/IdP)** with binding cookie & moderate session lifetime.  
- [ ] **Cloud MFA** enabled (TOTP/WebAuthn).  
- [ ] **Egress-only** tunnel; origin has no inbound.  
- [ ] **Nginx** policy chokepoint (headers, limits, ACLs).  
- [ ] **Docker** private bridges; no published ports for backends.  
- [ ] **Firewall**: loopback/LAN allow, else DROP.  
- [ ] **Logs** reviewed; **revoke/rotation** documented.

> **TL;DR:** The chain **mTLS → OTP/Access → App MFA** validates **device**, **user**, and **account** on **distinct layers**. This raises attack complexity and limits impact — classic **Defense-in-Depth**.
