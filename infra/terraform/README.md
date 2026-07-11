# Static-site hosting for `idptools.com`

Terraform for hosting the OAuth2/OIDC Debugger **client** as static content on
**S3 + CloudFront + ACM + Route 53**, mirroring the proven pattern already in
use in the reference account.

## What it creates

| Resource | Purpose |
|---|---|
| S3 bucket `www.idptools.com` | Public-read static website (origin). `index.html` is both index and error document → SPA-style fallback so the client-side `/callback` route works with no server. |
| S3 bucket `idptools-com-logs` | Dedicated CloudFront access-log bucket. |
| CloudFront distribution | Serves `idptools.com` + `www.idptools.com`, redirect-to-HTTPS, `PriceClass_All` (all edge regions), HTTP/2, IPv6, compression on. |
| ACM certificate (us-east-1) | Covers apex + `www`, DNS-validated. |
| Route 53 hosted zone | Authoritative DNS. Apex + `www` A/AAAA aliases to CloudFront, plus cert-validation records. |

### Intentional improvements over the reference

- **AAAA (IPv6) alias records** in addition to A (the distribution already has IPv6 enabled).
- **Compression on** (reference had it off) — smaller/faster for static assets.
- **Minimum TLS `TLSv1.2_2021`** (reference used the older `TLSv1.2_2018`).
- Cert validation records managed cleanly by Terraform (no stray records).

## Prerequisites

- Terraform ≥ 1.5, AWS CLI v2.
- AWS credentials for the **target account** with **write** access (the
  read-only creds used to analyze the reference account are not enough to
  apply). Set them via env vars, a profile, or SSO, and optionally set
  `aws_profile` in `terraform.tfvars`.

## Deploy — two-phase apply (because of the DNS chicken-and-egg)

ACM DNS validation only succeeds once the domain is delegated to this Route 53
zone, but you don't know the zone's name servers until it exists. So:

### Phase 1 — create the zone, get name servers

```bash
cd infra/terraform
terraform init
terraform apply -target=aws_route53_zone.this
terraform output name_servers
```

### Phase 2 — delegate at Namecheap (the one manual step)

In the Namecheap dashboard for `idptools.com` → **Domain → Nameservers →
Custom DNS**, enter the 4 name servers from `terraform output name_servers`.
Save, then wait for propagation (usually minutes; up to a couple hours):

```bash
dig +short NS idptools.com   # should return the Route 53 name servers
```

### Phase 3 — apply everything

```bash
terraform apply
```

This validates the certificate (now that DNS resolves), then creates the
distribution and alias records. `aws_acm_certificate_validation` will wait
until validation completes.

## Publish the site content

After apply, upload the built static client into the content bucket and
invalidate the CloudFront cache:

```bash
aws s3 sync ./client-static/ "s3://$(terraform output -raw content_bucket)/" --delete
aws cloudfront create-invalidation \
  --distribution-id "$(terraform output -raw cloudfront_distribution_id)" \
  --paths '/*'
```

> Producing `./client-static/` (the fully static, backend-free build of
> `/client`) is a separate code task: the browserify bundles currently inline
> `process.env.*` at build time, and the Express `/callback` route must be
> replaced by client-side handling (the `index.html` error-document fallback
> covers the routing). Track that separately from this infrastructure.

## Security notes (public repo)

- **No secrets live in this Terraform** — only the public domain name. Safe to
  commit to the public repo.
- **State is git-ignored** (`.gitignore` here). Terraform state can contain
  sensitive values and must never be committed. For team use, switch to the
  S3 remote backend stub in `versions.tf`.
- The content bucket is intentionally **public-read** (static, non-sensitive
  content), matching the reference. If you later want origin lockdown, the
  modern alternative is CloudFront **OAC** with a private bucket — but note
  that requires moving index/error routing into CloudFront custom error
  responses (403/404 → `/index.html`), since OAC uses the S3 REST endpoint,
  not the website endpoint.
```
