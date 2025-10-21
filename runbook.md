# Zero‑Trust selfhosted Cloud behind Cloudflare — Clean Runbook (40 Steps)

> **Scope (clean path):** Cloudflare proxied DNS → Edge mTLS (client cert) → Cloudflare Access (OTP/session) → **egress‑only** Cloudflare Tunnel → Nginx (loopback/LAN) → Cloud (Docker) → Redis/DB (private).  
> **Anonymized LAN:** `192.168.178.1:1011` (RFC 5737 TEST‑NET‑1) and loopback `127.0.0.1:1011`.  
> **Hostnames:** `cloud.example.com` (browser), `sync.example.com` (apps), `share.example.com` (public links).  
> **No personal data**; all identifiers are placeholders.

---

## Prerequisites
- Cloudflare account with Zero Trust (free/paid as needed).
- Domain delegated to Cloudflare (or ready to be delegated).
- Origin host with Docker/Compose and Nginx reverse proxy for Cloud.
- `cloudflared` available (package or Docker).

---

## 40 Steps (clean, renumbered)

### A — DNS & Zone (Edge perimeter)
1. **Export current DNS** at your existing DNS provider (backup).  
2. **Lower TTLs** for key records (A/AAAA/CNAME/MX/TXT) to **300 s** for smooth cutover.  
3. **Create the zone** in Cloudflare (`example.com`) and run the quick DNS import/scan.  
4. **Review imported records**; keep `@`/`www` as *DNS‑only* if you host a separate landing page.  
5. **Note Cloudflare NS** (e.g., `alice.ns.cloudflare.com`, `bob.ns.cloudflare.com`).  
6. **Change nameservers** at the registrar to the Cloudflare pair.  
7. **Verify delegation**:
   ```bash
   dig +short NS example.com @1.1.1.1
   dig +short NS example.com @8.8.8.8
   # Expect only the Cloudflare NS
   ```
8. **Remove legacy NS resource‑records** from the Cloudflare zone (delegation lives at registrar).  
9. **Create proxied records** for `cloud.`, `sync.`, and `share.` (orange cloud ON).

### B — Tunnel (egress‑only path to origin)
10. **Install/launch `cloudflared`** on the origin (package or Docker).  
11. **Authenticate:** `cloudflared tunnel login` and **create tunnel** (e.g., `nextcloud`).  
12. **Store credentials** (JSON) securely on the host (`/etc/cloudflared/<TUNNEL_ID>.json`).  
13. **Configure ingress** to the origin’s loopback TLS:
    ```yaml
    # /etc/cloudflared/config.yml
    tunnel: nextcloud
    credentials-file: /etc/cloudflared/<TUNNEL_ID>.json
    ingress:
      - hostname: cloud.example.com
        service: https://127.0.0.1:1011
        originRequest: { noTLSVerify: true }
      - hostname: sync.example.com
        service: https://127.0.0.1:1011
        originRequest: { noTLSVerify: true }
      - hostname: share.example.com
        service: https://127.0.0.1:1011
        originRequest: { noTLSVerify: true }
      - service: http_status:404
    ```
14. **Run as a service** (systemd) or Docker with `restart: unless-stopped`.  
15. **Route DNS to the tunnel** (Zero Trust → Tunnels → *Public hostnames*).  
16. **Verify status**:
    ```bash
    cloudflared tunnel info cloud
    docker logs --tail=100 cloudflared   # if Docker
    # Expect: connections to multiple Cloudflare edge colos
    ```

### C — Origin (Nginx + Docker)
17. **Bind Nginx** only to **loopback** and **LAN**:
    - `127.0.0.1:1011` (for tunnel)
    - `192.168.178.1:1011` (optional LAN maintenance)
18. **Enable origin TLS** at Nginx (LE or self‑signed); reverse‑proxy to Cloud:
    ```nginx
    server {
      listen 1011 ssl; http2 on;
      server_name _;
      ssl_certificate     /etc/nginx/certs/nextcloud.crt;
      ssl_certificate_key /etc/nginx/certs/nextcloud.key;
      add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;

      location / {
        proxy_pass http://cloud-app:80;
        proxy_set_header Host              $http_host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Port  $server_port;
        proxy_redirect off;
        client_max_body_size 0;
      }
    }
    ```
19. **Compose port‑mappings** (loopback + optional LAN):
    ```yaml
    # docker-compose.yml (service: nginx)
    ports:
      - "127.0.0.1:1011:1011"
      - "192.168.178.1:1011:1011"   # optional LAN
    ```
20. **Firewall (DOCKER‑USER)**: allow loopback and LAN, drop others:
    ```bash
    sudo iptables -I DOCKER-USER -i lo -p tcp --dport 1011 -j ACCEPT
    sudo iptables -I DOCKER-USER -s 192.0.2.0/24 -p tcp --dport 1011 -j ACCEPT
    sudo iptables -A DOCKER-USER -p tcp --dport 1011 -j DROP
    ```
21. **Verify bindings**:
    ```bash
    docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep nginx
    ss -lntp | grep ':1011'
    ```
22. **Private Docker networks** for Cloud ↔ Redis/DB (no public ports on backends).

### D — Nextcloud trust anchors
23. **trusted_domains** (inside app container as `www-data`):
    ```bash
    php occ config:system:set trusted_domains 0 --value=cloud.example.com
    php occ config:system:set trusted_domains 1 --value=sync.example.com
    php occ config:system:set trusted_domains 2 --value=192.168.178.1
    php occ config:system:set trusted_domains 3 --value=192.168.178.1:1011
    ```
24. **trusted_proxies** (Nginx container IP + loopback):
    ```bash
    php occ config:system:set trusted_proxies 0 --value=<NGINX_CONTAINER_IP>
    php occ config:system:set trusted_proxies 1 --value=127.0.0.1
    ```
25. **forwarded_for_headers** and **overwriteprotocol**:
    ```bash
    php occ config:system:set forwarded_for_headers 0 --value=HTTP_CF_CONNECTING_IP
    php occ config:system:set forwarded_for_headers 1 --value=HTTP_X_FORWARDED_FOR
    php occ config:system:set overwriteprotocol --value=https
    ```

### E — Edge mTLS + Access (Zero Trust)
26. **Enable Client Certificates** for `cloud.example.com` (SSL/TLS → Client Certs → *Require*).  
27. **Access application (Self‑hosted)** for `cloud.example.com`:
    - **Login methods:** OTP (or your IdP)  
    - **Session duration:** per policy  
    - **Cookies:** HTTPOnly; SameSite=Lax/Strict; (optional) binding cookie
28. **Optional WAF rule (strict mTLS)** — block unless `cf.tls_client_auth.cert_verified` is true:
    ```txt
    (http.host eq "cloud.example.com" and not cf.tls_client_auth.cert_verified)
    ```
29. **Issue client certs** (ECC P‑256): generate key/CSR; sign with Cloudflare Client CA (or your CA).  
30. **Package P12/PFX** with strong password; store securely.  
31. **Import P12** to client OS (e.g., Windows `Cert:\CurrentUser\My`).  
32. **Extract serial** (lowercase, no colons) for allowlisting.  
33. **Optional WAF allowlist** (Issuer + Serial + verified):
    ```txt
    (http.host eq "cloud.example.com"
      and not (
        cf.tls_client_auth.cert_verified
        and lower(cf.tls_client_auth.cert_issuer_dn) contains "your client ca name"
        and lower(cf.tls_client_auth.cert_serial) in {"<serial_lowercase_no_colons>"}
      )
    )
    ```
34. **Configure sync policy** (`sync.example.com`): bypass Access login, but keep mTLS/device posture as needed.  
35. **Configure share policy** (`share.example.com`): bypass or mild policy for public links.

### F — Verification, Monitoring, Hygiene, Rollback
36. **Test (no cert → blocked):**
    ```bash
    curl -Ik https://cloud.example.com
    # Expect: 403 at edge (mTLS required)
    ```
37. **Test (with cert → Access):**
    ```bash
    read -s -p "P12 password: " P; echo
    curl -Ik --cert client.p12 --cert-type P12 --pass "$P" https://cloud.example.com
    # Expect: 302 → /cdn-cgi/access/login/...
    ```
38. **Test LAN path (no Cloudflare):**
    ```bash
    curl -Ik https://192.168.178.1:1011/
    # Expect: 302 → /login
    ```
39. **Monitor logs:** `cloudflared` status, Cloudflare Zero Trust **Logs** (mTLS/Access decisions), Nginx & Cloud logs.  
40. **Secret hygiene & rollback:** remove working copies of P12; document rotation; rollback by pausing WAF rule or adjusting Access; tunnel down ⇒ origin stays non‑exposed; LAN remains controlled.

---

## Notes
- **Egress‑only** means no inbound ports on the origin; the tunnel pulls connections from Cloudflare.  
- **Defense‑in‑Depth:** device identity (mTLS) **before** user identity (Access), then egress‑only, then reverse‑proxy boundary, then explicit app trust anchors, then micro‑segmented backends.  
- **RFC 5737** addresses (`192.0.2.0/24`) are documentation‑safe.

