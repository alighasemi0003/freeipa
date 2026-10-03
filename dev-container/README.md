# FreeIPA local development container

Build FreeIPA **from this repository's source**, package it as RPMs, then run it
inside the **official** [freeipa-container](https://github.com/freeipa/freeipa-container)
systemd/`/data` runtime — without using `freeipa/freeipa-server` as a base image.

## One command

```bash
cd ~/freeipa
./dev-container/up.sh
```

This will:

1. Clone/update official `freeipa-container` into `dev-container/vendor/` (gitignored)
2. Build FreeIPA RPMs from the current local source tree
3. Build `local/freeipa-server:4.13.4-dev` (official Dockerfile + local RPM repo)
4. Start the **single** `freeipa-dev` container with named volume `freeipa-data`
5. Wait for DS/KDC/httpd, verify local RPMs, print access info

## Architecture

```text
docker compose
    │
    └── freeipa-dev                  (ONE service — not app+postgres+redis)
          │
          ├── systemd
          ├── 389 Directory Server   (FreeIPA directory DB — inside this container)
          ├── Kerberos KDC / kpasswd
          ├── Dogtag PKI / CA
          ├── Apache + FreeIPA Web UI / API
          └── BIND                   (optional; IPA_ENABLE_DNS=true only)
                 │
                 ▼
             /data  →  Docker volume freeipa-data
```

There is **no** separate PostgreSQL, MySQL, Redis, or LDAP container.

Fedora packages (389-ds, PKI, Apache, …) come from Fedora. **FreeIPA packages**
come only from the RPMs built out of this tree.

## Defaults

| Item | Value |
|------|--------|
| Image | `local/freeipa-server:4.13.4-dev` |
| Container | `freeipa-dev` |
| Volume | `freeipa-data` |
| Hostname | `ipa.ipa.test` |
| Domain | `ipa.test` |
| Realm | `IPA.TEST` |
| User | `admin` |
| Admin / DM password | `Secret123` (from `.env`) |
| Web UI | https://ipa.ipa.test/ipa/ui/ |
| Integrated DNS | **disabled** by default |

Copy/edit `dev-container/.env.example` → `.env` (created automatically by `up.sh`).

## Day-to-day commands

```bash
./dev-container/up.sh        # first start / full chain
./dev-container/rebuild.sh   # after source changes (keeps freeipa-data)
./dev-container/logs.sh
./dev-container/shell.sh
./dev-container/down.sh      # stop container, keep data
./dev-container/reset.sh     # destroy container + volume (asks confirmation)
```

## Windows browser / hosts

Do **not** rely on `localhost` as the FreeIPA hostname. Add this manually to the
Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`):

```text
127.0.0.1  ipa.ipa.test
```

Then open https://ipa.ipa.test/ipa/ui/ (accept the FreeIPA CA warning).

## DNS note (WSL)

Integrated FreeIPA DNS is **off** by default (`IPA_ENABLE_DNS=false`). Installation
uses `--no-ntp` and does **not** pass `--setup-dns`. Resolve the server via hosts.

Host port **53** is usually taken by `systemd-resolved` in WSL.

To enable integrated DNS intentionally:

```bash
# in .env
IPA_ENABLE_DNS=true
```

Then `up.sh` / `rebuild.sh` load `docker-compose.dns.yml` (publishes 53/tcp+udp),
append `--setup-dns --auto-forwarders`, and fail early if port 53 conflicts.

## Published ports (default, DNS off)

| Port | Protocol |
|------|----------|
| 80 | HTTP |
| 443 | HTTPS |
| 389 | LDAP |
| 636 | LDAPS |
| 88 | Kerberos TCP/UDP |
| 464 | kpasswd TCP/UDP |

## Persistence

`freeipa-data` survives image rebuilds. Flow after code changes:

```text
edit source → ./dev-container/rebuild.sh → new RPMs/image → recreate container → same /data
```

`up.sh`, `rebuild.sh`, and `down.sh` never delete the volume.
Only `./dev-container/reset.sh` deletes it (with confirmation).

## Layout

```text
dev-container/
├── up.sh / rebuild.sh / down.sh / logs.sh / shell.sh / reset.sh
├── Dockerfile.builder
├── Dockerfile.runtime          # pointer — generated at build time
├── docker-compose.yml          # single service: freeipa
├── docker-compose.dns.yml      # optional DNS ports
├── .env.example
├── scripts/
├── output/rpms/                # gitignored
├── vendor/freeipa-container/   # gitignored
└── .build/                     # gitignored
```

## Requirements

- Docker + Compose available inside WSL
- Network access to pull Fedora base images (`FEDORA_BASE_IMAGE=fedora`) and clone `freeipa-container`
- First RPM build can take a long time

No interactive `sudo` is required for the happy path.
