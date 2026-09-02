# DCK Geo/VPN Relay

Public, automated IP-range relay for DigiCompKala.

This repository builds local-ready lists for a lightweight pre-WordPress warning policy:

- Iranian IPv4/IPv6 ranges from RIPE NCC delegated data.
- Known VPN ranges from X4BNet.
- Published egress/server IPs for several commercial VPN providers.
- Official Tor exit nodes.
- A public working-proxy feed.
- Google crawler/fetcher ranges are imported from `digicompkala/dck-google-ipranges-relay` only as protected ranges and are never added to the warning list.

## Policy

The intended site policy is informational, not blocking:

- Iran IP -> allow directly.
- Non-Iran IP not matched as VPN/proxy/Tor -> allow directly.
- Non-Iran IP matched as VPN/proxy/Tor -> show a lightweight warning before WordPress.
- The visitor may continue with the same connection.
- Google, Torob, Emalls, and the DigiCompKala origin are protected from the warning candidate list.

## Generated files

- `dist/iran-v4.txt`
- `dist/iran-v6.txt`
- `dist/vpn-proxy-v4.txt`
- `dist/vpn-proxy-v6.txt`
- `dist/tor-v4.txt`
- `dist/tor-v6.txt`
- `dist/dck-geo-vpn-report.json`

## Safety model

The builder validates every network, rejects private/reserved inputs, collapses duplicates, subtracts Iranian address space from VPN/proxy candidates, subtracts protected networks (Google, Torob, Emalls, and origin), enforces sanity checks, and only publishes a complete build.

The repository does not change the web server or WordPress. VPS integration is a separate step after the generated lists are audited.

## Update cadence

GitHub Actions rebuilds the lists hourly. If a required upstream source or validation step fails, the workflow fails and the previously published `dist/` files remain unchanged.
