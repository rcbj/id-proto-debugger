# Infrastructure (Terraform, containerized)

All Terraform runs **inside a Docker container** — the only thing on your host
(or the CI runner) is Docker. Same pattern as the static-content deploy pipeline
in `../deploy`.

## Layout

| Path | What |
|---|---|
| `terraform/` | **prod** — idptools.com (apex + www) |
| `terraform-test/` | **test** — test.idptools.com (subdomain of the prod zone) |
| `Dockerfile` | Terraform + AWS CLI runner image |
| `entrypoint.sh` | runs `init`/`plan`/`apply`/… for one env inside the container |
| `terraform-local.sh` | host wrapper: builds the image, bridges your SSO creds, runs it |
| `bootstrap-state.sh` | one-time creation of the S3 state bucket |

## Remote state

State lives in S3: **`s3://idptools-terraform-state-721850476504`**
(versioned, encrypted, private), keys `idptools.com/prod.tfstate` and
`idptools.com/test.tfstate`. Locking is **S3-native** (`use_lockfile`,
Terraform ≥ 1.11) — no DynamoDB. This is what lets CI runs be meaningful; the
bucket was created once via `bootstrap-state.sh` and is intentionally not
managed by Terraform.

## Run locally

Host needs **Docker** and the **AWS CLI**; sign in first:

```bash
aws sso login          # or: aws login

./infra/terraform-local.sh test plan     # env action
./infra/terraform-local.sh prod plan
./infra/terraform-local.sh prod apply
```

`env` = `prod|test` (default `test`), `action` =
`init|validate|plan|apply|destroy|output` (default `plan`). If your Docker needs
root, the wrapper auto-falls back to `sudo docker` (or set `DOCKER="sudo docker"`).

## CI

`.github/workflows/terraform.yml` builds the same image and runs it:

- **PRs** touching `infra/**` → `plan` for **both** environments (read-only).
- **Manual dispatch** → choose environment + `plan`/`apply`.

CI authenticates with the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` repo
secrets (local runs use your SSO session instead).
