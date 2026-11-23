# Reaching cairn from away: HTTPS with a real certificate

cairn's dashboard and API listen on plain HTTP (`http://<main box>:8929`). That's fine on your own
network. To reach cairn from anywhere else, from a browser or the Android app, put it behind
**HTTPS with a certificate from a public authority**. [Let's Encrypt](https://letsencrypt.org/) is
the free, supported way to get one.

## What the Android app accepts

| Address | Accepted? |
| --- | --- |
| `http://` to a private address (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, `100.64.x.x`, link-local, loopback) or a `.local` / `.lan` / `.home.arpa` name | Yes: home network only |
| `https://` with a certificate Android already trusts (Let's Encrypt, any public CA) | Yes: anywhere |
| `http://` to a public address | **No** |
| `https://` with a self-signed certificate, or one from your own private CA | **No** |

Self-signed certificates aren't supported, and there's no "trust this certificate" button. Every
request carries a cairn token, and an admin token can start backups and restores. A connection the
app can't verify could hand that token to whoever is in the middle. "Trust on first use" (pinning the
certificate the first time you connect) was considered and turned down: the first connection is
unprotected, and a renewed certificate looks the same as an attack, so people learn to tap "accept".
A real certificate avoids all of that and costs nothing.

## The recommended setup

1. **A name.** Any domain or subdomain you control, e.g. `cairn.example.com`, pointing at your home
   connection. A dynamic-DNS name works too.
2. **A reverse proxy with Let's Encrypt**, on the main box or anywhere that can reach it. It gets and
   renews the certificate and forwards to `http://<main box>:8929`. Any of these do it:
   - **Caddy**: certificates are automatic. The whole config:
     ```
     cairn.example.com {
         reverse_proxy 192.168.1.5:8929
     }
     ```
   - **Nginx Proxy Manager**: add a proxy host for `cairn.example.com` → `192.168.1.5:8929`, then
     on the SSL tab request a Let's Encrypt certificate with "Force SSL" on.
   - **Traefik**, or **nginx + certbot**: the same idea, with a Let's Encrypt resolver or `certbot --nginx`.
3. **Forward ports 80 and 443** from your router to the proxy (80 is for Let's Encrypt's HTTP check).
   If you'd rather not open ports, use a **DNS challenge** (Caddy, Traefik and certbot all support
   one with most DNS providers), or a tunnel such as Cloudflare Tunnel or Tailscale Funnel, which
   bring their own trusted certificate.
4. **Tell cairn its public address**, so pairing codes include it (see "Pairing a phone" in the
   README):
   ```
   CAIRN_PUBLIC_URL=https://cairn.example.com
   CAIRN_LAN_URL=http://192.168.1.5:8929
   ```
   The phone then tries the LAN address at home and the public one away, and uses whichever answers.

Have the proxy pass `X-Forwarded-Proto` and `X-Forwarded-Host` (Caddy and Nginx Proxy Manager do by
default), so cairn knows the address it was opened on.

## Never leave the network: a VPN

If cairn should only be reachable by you, skip the public name and use a VPN (WireGuard, Tailscale).
On the VPN the phone uses a private address over `http://`, which the app accepts. Tailscale's
`100.64.x.x` addresses count as private.

## Checking it

- `https://cairn.example.com/api/v1/identify` opens in a phone browser with no certificate warning.
- In the app: Settings → Addresses → **Add address**, enter the `https://` address. The app checks
  it against this server's name and your token before saving.
