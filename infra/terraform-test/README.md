# Test environment — `test.idptools.com`

Terraform for the **test** static site, mirroring the prod pattern in
`../terraform` (S3 website + CloudFront + ACM), with two differences:

- It is a **subdomain** of the already-delegated `idptools.com` zone, so it
  **reuses the existing hosted zone** via a data source instead of creating a
  new one — no Namecheap/name-server step, and ACM DNS validation succeeds on
  the first apply.
- Cheaper defaults for a test env: `PriceClass_100`, no `www` alias.

State is completely separate from prod (`../terraform`). The two configs touch
the same hosted zone but manage disjoint record sets (prod: apex + www; test:
`test.idptools.com`), so they never conflict.

## Deploy

State is remote (S3, key `idptools.com/test.tfstate`). Run via the
containerized runner (see `../README.md`) — no host Terraform, no cred bridging
by hand:

```bash
aws sso login                              # or: aws login
./infra/terraform-local.sh test plan
./infra/terraform-local.sh test apply
```

Single apply — no two-phase dance, because the parent zone is already live.

## Outputs

- `content_bucket` — upload the built static client here
- `cloudfront_distribution_id` — for cache invalidations
- `site_url` — https://test.idptools.com

## Publishing content

Use the containerized pipeline with the test target:

```bash
DEPLOY_ENV=test ./deploy/deploy-local.sh
```
