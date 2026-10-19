# Terraform (optional)

**Not required to run this project.** `docker compose up` on your own
machine is the intended way to use this repo — see the top-level
[`README.md`](../README.md). This folder is a minimal, optional path to
stand the same stack up on a single AWS EC2 instance, for anyone who wants
to demo it from a public URL instead of localhost.

It provisions exactly one thing: an EC2 instance with Docker + the Compose
plugin installed, that clones this repo and runs `docker compose up -d
--build` via user-data on first boot. No RDS/OpenSearch Service/managed
Redis — everything still runs in containers on the one box, same as local.
That keeps this genuinely optional and cheap (~$0.08/hr on a `t3.large`) to
try, rather than a second infrastructure project bolted onto a detection
engineering one.

## Usage

```bash
cd terraform
terraform init
terraform apply \
  -var="key_name=<your EC2 key pair name>" \
  -var="allowed_ssh_cidr=<your IP>/32" \
  -var="repo_url=<git URL of your fork/push of this repo>"
```

`terraform output` prints the instance's public IP. After a few minutes
(image builds + OpenSearch startup), `http://<public_ip>/grafana/` should be
reachable the same way `http://localhost/grafana/` is locally.

## What it does NOT do

- No TLS (see the main README's "Security notes" — add a reverse proxy with
  real certs, e.g. via Let's Encrypt, before leaving this running publicly).
- No managed database/search/queue services — this is a single-box demo
  deployment, not a production reference architecture.
- No secrets management — the same dev credentials baked into
  `docker-compose.yml` are used. Change them before exposing this publicly
  for more than a quick demo.

## Tear down

```bash
terraform destroy
```
