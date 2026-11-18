# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.1.0] – 2026-11-18

### Added
- **Update** button (same password as New PC): checks the GitHub repo for a new version and, if there is one,
  downloads it and rebuilds the containers automatically. The rebuild runs as a systemd job on the server,
  so it finishes even while the page's own container is replaced. If the rebuild can't start, the server
  goes back to the running version.
- Installed version and last update result shown on the page; rebuild output logged to `update.log`.

## [2.0.0] – 2026-11-18

### Added
- `config.json`: all site-specific settings (server address, VPN subnet, client template, NAT, traffic
  light stations) in one file, mounted into both containers. The code no longer contains site values.
- `app/common.py`: shared settings loader, OpenVPN status reader, icons, theme, top bar and HTTP helpers.
- Shared top bar with tabs to switch between "VPN clients" and "Traffic lights". The traffic light tab is
  hidden when `traffic_lights` is not configured.
- Automatic VPN address for new PCs: the lowest free address in the VPN subnet (not used by any ccd
  file or connected client). The "New PC" dialog shows it before creating.
- Password hashing (PBKDF2-SHA256, 200 000 iterations). Separate passwords:
  - admin password (enable/disable, restart OpenVPN): unchanged, now stored as a hash in
    `/etc/openvpn/server/status-password`; an old plain-text file is converted on start;
  - "New PC" password: its own password, stored only as a hash in the code (`CREATE_PASSWORD_HASH`).
- CLI commands: `vpn_status.py set-admin-password` and `vpn_status.py hash-password`.
- New `.ovpn` profiles also inline the `tls-auth` / `tls-crypt` key when the template uses one.
- Success messages after enabling or disabling a client.
- GPL-3.0 license (`LICENSE`) and SPDX headers in the source files.
- README: settings, passwords, "New PC" steps, devices.txt format.

### Changed
- "New client" is now "New PC" and creates PC clients only: just a name and the password are asked.
  Names are cleaned automatically (lowercase, spaces become `-`, `client-` is added).
- VPN page redesign: one card per router with the LAN line (VPN subnet ⇄ real subnet for NAT sites)
  and two separate panels, **Router** and **Components**. Each component shows its state
  (reachable / no reply / not checked), its address, its real address inside the vehicle and its latency.
  Expected components from devices.txt are listed even before a scan. PCs are shown in their own table.
- Both pages use the same theme (light and dark), layout, buttons and pills, and work on phones.
- Scripts moved to `app/vpn_status.py` and `app/tl_status.py`; Dockerfile and compose.yaml updated.
- Both servers wait and retry until the VPN server address is up.
- Unknown URLs return 404 instead of the main page.
- Form posts are accepted from the configured page address or the request's own host (was: only the
  configured address).

### Removed
- Router creation from the web page (zip bundles, server routes, pushing routes to PCs).
- Hard-coded list of PC client names: PCs are detected by a ccd file without `iroute`; exceptions go in
  `pc_clients` in config.json.

### Fixed
- Traffic light page: a short Modbus packet could crash the packet reader thread, stopping all live
  updates until the container restarted.
- File handles are now closed after reading.
