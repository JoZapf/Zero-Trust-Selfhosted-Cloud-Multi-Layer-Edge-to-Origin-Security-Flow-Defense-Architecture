### End-to-End Request Flow  
#### From Public Internet through Cloudflare Zero Trust to Dockerized Nextcloud

The diagram below shows the full path of a request from browser or sync app on the public Internet,
through Cloudflare (proxied DNS, TLS, mTLS, WAF, Access) and the egress-only Cloudflare Tunnel,
down to the local nginx reverse proxy on `127.0.0.1:1011` / `192.168.178.1:1011` and finally into the
internal Docker network where the Nextcloud app, Redis and the database run. Each hop represents a
separate trust and control layer in the overall Zero-Trust design.

```mermaid
%%{init: {'theme': 'dark'}}%%
flowchart TB
    %% Clients / Internet
    subgraph INTERNET["Internet / Clients"]
        CBrowser["Browser Clients<br>(Desktop / Mobile)"]
        CApps["Sync / Talk Apps"]
    end

    %% Public DNS / Cloudflare
    subgraph CF_DNS["Public DNS / Cloudflare Zone"]
        DNSCloud["cloud.your-domain.com<br>CNAME -> <tunnel-id>.cfargotunnel.com"]
        DNSSync["sync.your-domain.com<br>CNAME -> <tunnel-id>.cfargotunnel.com"]
        DNSShare["share.your-domain.com<br>CNAME -> <tunnel-id>.cfargotunnel.com"]
    end

    subgraph CF_EDGE["Cloudflare Edge (443/tcp)"]
        CFProxy["Proxied DNS (orange cloud)"]
        CFTLS["TLS Termination"]
        CFmTLS["Client mTLS (cloud/sync)<br>Client-Cert + Serial Allowlist"]
        CFWAF["WAF Rules<br>mTLS Rules, Rate Limits, Geo/IP, UA"]
        CFAccess["Cloudflare Access (OTP / IdP)<br>for cloud.your-domain.com"]
    end

    %% Tunnel component
    subgraph CF_TUNNEL["Cloudflare Tunnel"]
        TunnelCloudflared["cloudflared on origin host<br><tunnel-id>.cfargotunnel.com"]
    end

    %% Origin host + nginx
    subgraph ORIGIN_HOST["Origin Host (Selfhosted)"]
        subgraph ORIGIN_NET["Loopback / LAN"]
            Loopback["127.0.0.1:1011<br>HTTPS (nginx)"]
            LAN["192.168.178.1:1011<br>HTTPS (nginx, LAN maintenance)"]
        end

        subgraph NGINX["nginx Reverse Proxy Container"]
            Nginx8085["listen 1011 ssl http2;<br>server_name _;<br>ssl_certificate /etc/nginx/certs/cloud.crt"]
            NginxProxy["location / -> proxy_pass http://cloud-app:80;<br>X-Forwarded-*, HSTS, client_max_body_size 0"]
        end
    end

    %% Docker network / application layer
    subgraph DOCKER_NET["Docker Network: internal only"]
        subgraph APP["Nextcloud App Container"]
            NCApp["cloud-app:80<br>PHP/Apache, Nextcloud"]
        end

        subgraph REDIS["Redis Container"]
            Redis["redis:6379<br>Locks / Caching"]
        end

        subgraph DB["DB Container"]
            DBService["mariadb:3306<br>Nextcloud DB"]
        end
    end

    %% Internet → DNS
    CBrowser -->|"https://cloud.your-domain.com"| DNSCloud
    CBrowser -->|"https://sync.your-domain.com"| DNSSync
    CBrowser -->|"https://share.your-domain.com"| DNSShare

    CApps -->|"Server: sync.your-domain.com"| DNSSync

    %% DNS → Edge
    DNSCloud --> CFProxy
    DNSSync  --> CFProxy
    DNSShare --> CFProxy

    %% Edge Pipeline
    CFProxy --> CFTLS
    CFTLS --> CFmTLS
    CFmTLS --> CFWAF

    %% cloud.your-domain.com → Access
    CFWAF -->|"Host: cloud.your-domain.com<br>mTLS OK + serial allowlisted"| CFAccess
    CFAccess -->|"Session OK"| CF_TUNNEL

    %% sync.your-domain.com → direkt zum Tunnel (mTLS/WAF)
    CFWAF -->|"Host: sync.your-domain.com<br>mTLS OK (Apps)"| CF_TUNNEL

    %% share.your-domain.com → mild policy
    CFWAF -->|"Host: share.your-domain.com<br>Public Links / mild WAF"| CF_TUNNEL

    %% Tunnel → Origin
    CF_TUNNEL -->|"HTTPS 443 → tunnel"| TunnelCloudflared
    TunnelCloudflared -->|"ingress: service https://127.0.0.1:1011<br>noTLSVerify: true"| Loopback

    %% Loopback / LAN → nginx
    Loopback --> Nginx8085
    LAN -->|"LAN admin / maintenance"| Nginx8085

    Nginx8085 --> NginxProxy
    NginxProxy -->|"HTTP 80"| NCApp

    %% App → Redis / DB
    NCApp -->|"TCP 6379"| Redis
    NCApp -->|"TCP 3306"| DBService

```