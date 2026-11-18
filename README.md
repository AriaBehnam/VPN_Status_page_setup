# VPN status pages

Two small web pages that run in Docker on the OpenVPN server (no extra Python packages).

| Page | Address | What it shows |
|---|---|---|
| VPN clients | http://10.8.0.1:8081/ | Routers (LAN, router, components behind it, scan, latency), PCs, enable/disable, restart, **New PC** |
| Traffic lights | http://10.8.0.1:8082/ | Live fleet manager → main PLC → traffic light traffic, read passively from `tun0` |

```
config.json        all site settings (addresses, client names, stations) – edit this, not the code
app/common.py      shared settings loader, theme, top bar, OpenVPN status file reader, HTTP helpers
app/vpn_status.py  VPN clients page
app/tl_status.py   traffic light page
```

## Settings (config.json)

| Key | Meaning |
|---|---|
| `title` | name shown in the top bar |
| `server_ip`, `vpn_network` | VPN server address and VPN subnet |
| `pc_host_range` | host numbers new PCs may get, `[2, 255]` = .2 – .254 |
| `pc_clients` | clients to show as PCs even without a ccd file (normally empty: a ccd file without `iroute` = PC) |
| `client_template` | `client.conf` whose server settings are copied into new PC profiles |
| `profiles_dir` | where new `.ovpn` files are kept |
| `nat` | 1:1 NAT pool and the real LAN behind it |
| `traffic_lights` | fleet manager, main PLC and stations for the traffic light page; remove it to hide that page |

After a change: `docker compose restart`.

## Run

```sh
docker compose up -d --build
```

## Update button

**Update** on the VPN page (same password as New PC) checks GitHub for a new version. If there is one it is
downloaded (`git fetch` + fast-forward) and the containers are rebuilt with `docker compose up -d --build`;
the pages are back after about a minute. The result of the last update is shown in the dialog and logged
to `update.log` in the project folder.

Needed once on the server:

```sh
apt install -y git                                     # if git is missing
git clone https://github.com/AriaBehnam/VPN_Status_page_setup.git /opt/vpn-status
cd /opt/vpn-status && docker compose up -d --build     # always start it from this clone
```

Local changes on the server (e.g. in `config.json`) are kept. If a new version changes the same file,
the update stops with a message and nothing is changed.

## Passwords

Only PBKDF2-SHA256 hashes are stored.

- **Admin password** (enable/disable a client, restart OpenVPN): hash in `/etc/openvpn/server/status-password`.
  An old plain-text password in that file is converted to its hash on start, so it keeps working.
  Change it with:
  `docker compose exec -it vpn-status python3 /app/vpn_status.py set-admin-password`
- **New PC and Update password**: hash in `CREATE_PASSWORD_HASH` in `app/vpn_status.py`.
  Make a new hash with `docker compose exec -it vpn-status python3 /app/vpn_status.py hash-password`.

## New PC

Only a name and the password are asked. The page then:

1. picks the lowest free VPN address in 10.8.0.0/24 automatically,
2. creates the certificate with Easy-RSA,
3. writes the ccd file (fixed address + routes to every router LAN),
4. builds a single `.ovpn` file from the `client_template` settings and offers it for download.

## devices.txt

`/etc/openvpn/server/devices.txt` names the components behind each router, one line per router:

```
client-site1    | .2 PLC, .253 router
client-vehicle1 | .2 PLC, .10 HMI, .1 router | 192.168.1.0/24
```

The optional last part is the real LAN inside the vehicle for 1:1 NAT sites.

## License

GNU General Public License v3.0 or later – see [LICENSE](LICENSE).
