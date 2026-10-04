# Running MISP / OpenCTI later (VPS guide)

The pipeline is fully useful without a CTI platform - this document covers the
day you want one and point the connectors at it. **Do not** run these on a
machine with under 4 GB free RAM.

## Sizing

| Stack | Minimum | Comfortable | Notes |
| --- | --- | --- | --- |
| MISP only | 4 GB | 8 GB | MySQL + Redis + workers |
| MISP + OpenCTI | 16 GB | 16-32 GB | adds OpenSearch, RabbitMQ, MinIO |

Any Ubuntu 22.04/24.04 VPS from Hetzner / DigitalOcean / Vultr works. Oracle
Cloud Always Free (4 ARM cores, 24 GB) can run the full stack if you get
capacity in your region.

## MISP

Follow the official [misp-docker](https://github.com/MISP/misp-docker) compose:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"   # re-login afterwards

git clone https://github.com/MISP/misp-docker.git && cd misp-docker
cp template.env .env
# Edit .env at minimum:
#   CORE_BASE_URL=https://misp.yourdomain.tld
#   ADMIN_EMAIL / ADMIN_PASSWORD (long, unique)
#   MYSQL_ROOT_PASSWORD / MYSQL_PASSWORD (long, unique)
docker compose up -d
```

Then put TLS in front (Caddy is the shortest path):

```bash
caddy reverse-proxy --from misp.yourdomain.tld --to 127.0.0.1:80 --tls you@yourdomain.tld
```

Create an API key in MISP (*Administration → Auth keys*) and wire up the
connector on the machine that runs the pipeline:

```powershell
pip install pymisp
$env:MISP_URL = "https://misp.yourdomain.tld"
$env:MISP_API_KEY = "<auth key>"
python -m tip push --misp --days 7
```

In GitHub Actions you would add `MISP_URL` / `MISP_API_KEY` as repository
secrets and a `push` step to `sync.yml`.

## OpenCTI

Use the official compose from the [OpenCTI repository](https://github.com/OpenCTI-Platform/docker)
(`docker/docker-compose.yml`), 16 GB RAM recommended. Preferred ingestion
path: *Data → Ingestion → Import* and upload `dist/stix/bundle.json` (or set up
an OpenCTI ingestion connector watching that file). The bundled
`python -m tip push --opencti` connector is experimental - verify against your
OpenCTI version.

## GitHub Codespaces (playground, no server)

For learning the MISP UI without renting anything: open this repo in a
Codespace, install docker, and follow the MISP steps above. Codespaces are
ephemeral (data dies with the codespace), so this is for exploration only.

## Hardening checklist

- Firewall: expose only 22/80/443; never expose MySQL/Redis/OpenSearch.
- Strong unique passwords everywhere; change every default.
- TLS everywhere (Caddy/nginx + Let's Encrypt or a Cloudflare Tunnel).
- Keep images patched: `docker compose pull && docker compose up -d`.
- Back up volumes regularly (`docker compose exec db mysqldump ...` for MISP).
- Feed data here is TLP:CLEAR; widen event distribution in MISP deliberately.
