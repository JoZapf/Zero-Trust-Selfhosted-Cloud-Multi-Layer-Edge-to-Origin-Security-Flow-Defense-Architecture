# Zero-Trust Policy Table – your-cloud-domain.com

## Overview

This table describes the zero-trust-oriented separation of the three main hosts:

- `cloud.your-domain.com` – Full browser access to the Nextcloud instance
- `sync.your-domain.com`  – Sync/API access for Nextcloud and Talk apps
- `share.your-domain.com` – Access to shared/public links (shares)

---

## Zero-Trust Policy Tabele

| Host                  | Purpose / Scope                              | Typical Clients                        | Cloudflare-Layer                                           | Cloud-Layer                                   | Zero-Trust-Benefit (short)                                                                 |
|-----------------------|--------------------------------------------|-----------------------------------------|------------------------------------------------------------|--------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `cloud.your-domain.com` | Full access via browser                      | Browser (Desktop/Laptop)                | **mTLS Client-Cert** + WAF Serial-Whitelist + Access/OTP   | Login + **2FA** + Roles & Groups                     | Most privileged path, maximum hardening (mTLS → OTP → 2FA).                         |
| `sync.your-domain.com`  | **Sync + API** for Cloud, Messenger- & Service-Apps   | Cloud-Clients, Messenger, given. WebDAV    | TLS, WAF-Rules for App-Traffic (e. g. Path-/User-Agent-Focus, Rate-Limit, optional IP/Geo) | App passwords, device tokens, given. Restricted groups | Separation of UI & API: smaller scope, clearer policies for machine/app access.       |
| `share.your-domain.com` | **Public/semi-public shares**     | Browsers of external recipients         | TLS, WAF streng auf `/s/<token>` + Rate-Limits, no mTLS, no OTP, no Login-Flow        | Share tokens, expiration dates, optional share passwords   | Public scope isolated: Attacks on shares do not directly affect the `cloud.` login interface.

---

## cloud.yourdomain.com
```mermaid

flowchart LR
    CClient["cloud.your-domain.com /<br>Browser-Client"]
    CCF["Cloudflare Edge"]
    CmTLS["mTLS Client Auth<br>(B1)"]
    CWAF["WAF Serial Whitelist (B2)"]
    CAccess["Cloudflare Access OTP (B3)"]
    CApp["Cloud Login + 2FA (B4)"]
    CUser["Cloud UI"]

    CBlock1["BLOCK: mTLS Error"]
    CBlock2["BLOCK: WAF Block"]
    CBlock3["BLOCK: OTP Error"]

    CClient -->|HTTPS Request| CCF
    CCF --> CmTLS
    CmTLS -->|Cert OK| CWAF
    CmTLS -->|no/invalid Cert| CBlock1
    CWAF -->|Serial allowed| CAccess
    CWAF -->|Serial not allowed| CBlock2
    CAccess -->|OTP OK| CApp
    CAccess -->|OTP failed| CBlock3
    CApp --> CUser
```
- **B1 – mTLS Client Auth:** Only devices with a valid client certificate can reach the perimeter (device trust).
- **B2 – WAF Serial Whitelist:** Even if certificates are leaked, only a defined number of devices are allowed (least privilege/fine-grained device scope).
- **B3 – Cloudflare Access / OTP:** Additional identity/session security above the device certificate (user trust, protection against pure device copies).
- **B4 – Nextcloud Login + 2FA:** Third line of defense – user account remains protected even if certificate or OTP are compromised (account trust).

## sync.yourdomain.com
```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    SClient["sync.your-domain.com /<br>Cloud & Service Apps"]
    SCF["Cloudflare Edge"]
    SmTLS["mTLS Client Auth<br>(Device Trust)"]
    SWAF["WAF API/Sync Policy (B5)<br>Rate Limits, UA, Geo/IP"]
    STunnel["Cloudflare Tunnel"]
    SNGINX["Cloud-Nginx"]
    SAPP["Nextcloud WebDAV / Sync (B6)<br>App Passwords / Tokens"]
    SAccess["Sync Successful"]

    SBlock0["BLOCK: mTLS failed / no client cert"]
    SBlock1["BLOCK: WAF Ratelimit / Signature"]
    SBlock2["BLOCK: Cloud Auth Error<br>(Token invalid / revoked)"]

    SClient -->|HTTPS Request| SCF
    SCF --> SmTLS

    SmTLS -->|Client cert OK| SWAF
    SmTLS -->|No / invalid cert| SBlock0

    SWAF -->|Suspicious traffic / DoS| SBlock1
    SWAF --> STunnel
    STunnel --> SNGINX --> SAPP

    SAPP -->|Token valid| SAccess
    SAPP -->|Token invalid / revoked| SBlock2
```
- **B5 – API/Sync WAF:**  
  Separation of UI and machine access; targeted limits and signatures for app traffic (paths, user agent, rate limits, geo/IP) instead of generic web rules.

- **B6 – App passwords & tokens:**  
  Device- and app-specific credentials, independent of the main login (scoped credentials, easy revocation of individual devices).


## share.yourdomain.com
```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart LR
    ShClient["share.your-domain.com /<br>Extern Browser-Client"]
    ShCF["Cloudflare Edge"]
    ShWAF["WAF Share Policy (B7)"]
    ShTunnel["Cloudflare Tunnel"]
    ShNGINX["Cloud-Nginx"]
    ShAPP["Cloud Share Endpoint (B8)"]
    ShAccess["Access to Shared Reccources"]

    ShBlock1["BLOCK: Ratelimit / IP Block"]
    ShBlock2["BLOCK: Share Invalid"]

    ShClient -->|"GET / s /< Token >"| ShCF
    ShCF --> ShWAF
    ShWAF -->|To Many Requests / Bad IP| ShBlock1
    ShWAF --> ShTunnel
    ShTunnel --> ShNGINX --> ShAPP
    ShAPP -->|Token Valid,<br>Password OK| ShAccess
    ShAPP -->|Token Invalid/Expired/Password wrong| ShBlock2
```
- **B7 – Share WAF:** Strong focus on `/s/<token>` paths with hard rate limiting – reduces the risk of token brute force attacks and misuse of public links.
- **B8 – Isolated Share Scope:** Public access is logically separated from `cloud.your-domain.com` – attacks on shares do not directly affect the hardened login frontend.

---

### Zero-Trust Comparison: Registration Plane vs. Data/Sync Plane
>cloud.your-domain.com → Registration Plane (browser login, mTLS + OTP + 2FA)

>sync.your-domain.com → Data / Sync Plane (app/sync access with mTLS)
---
| Plane / Layer                | Host                  | Device Trust                                                                                                          | User / Account Trust                                                                                                             | Zero-Trust Meaning                                                                                                                                                                                                                  |
|-----------------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Registration Plane**      | `cloud.your-domain.com` | Enforced via **mTLS** (client certificates + serial allowlist).                                                      | **User trust:** Cloudflare Access / OTP<br>**Account trust:** Nextcloud login + 2FA                                             | Only known, certificate-bound devices are allowed to issue new session / app tokens. Entry into the system is tightly bound to the specific device and user identity (strong registration perimeter).                                |
| **Data / Sync Plane (mTLS)**| `sync.your-domain.com`  | Also enforced via **mTLS** (client certificates + serial allowlist); every sync request is bound to a specific device. | **User / account trust:** App token (app password) **plus** WAF (rate limits, UA filters, geo/IP filters) as an additional layer. | Runtime access is both **token-bound** and **device-bound**. A compromised token alone is not sufficient – without the corresponding device certificate, the mTLS policy blocks access. This further reduces the per-account/per-device attack surface. |

---
