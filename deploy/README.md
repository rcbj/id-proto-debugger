# Static site build + deploy (containerized)

Builds the OAuth2/OIDC Debugger **client** as static content and deploys it to
the `idptools.com` S3 + CloudFront hosting created in `infra/terraform/`.

The entire pipeline runs **inside a Docker container** — the only thing that
runs on your host (or the CI runner) is Docker. The same image is used locally
and in GitHub Actions.

## What the container does (`deploy/entrypoint.sh`)

1. `npm run build` in `client/` → produces `client/dist/`:
   - browserifies the 7 feature bundles (envify inlines `CONFIG_FILE`),
   - copies `client/public/` assets,
   - resolves the `<!--#include ...-->` header/footer partials that `server.js`
     normally handles at request time,
   - writes a `dist/callback/` shim so the OAuth2 `redirect_uri` (`/callback`)
     forwards to `debugger2.html` with no server.
2. `aws s3 sync dist s3://www.idptools.com --delete`
3. `aws cloudfront create-invalidation --distribution-id E1C72FI2JLYGWW --paths /*`

## Auth model

| Context | How it authenticates to AWS |
|---|---|
| **Local** (`deploy-local.sh`) | Your **AWS SSO / `aws login` session** (Identity Center OIDC). The wrapper resolves it to short-lived creds on the host and passes them to the container as env vars — no static keys, no `~/.aws` mount, nothing written to disk. |
| **CI** (`website-deploy.yml`) | **Static keys** from repo secrets (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`). |

The container entrypoint is identical for both — it just consumes whatever AWS
credential env vars it is handed.

## Run it locally

Host needs **Docker** and the **AWS CLI**. Sign in to your AWS session first,
then run:

```bash
aws sso login            # or: aws login   (refresh your SSO session)

# PROD (idptools.com): build + deploy
./deploy/deploy-local.sh

# TEST (test.idptools.com): build + deploy
DEPLOY_ENV=test ./deploy/deploy-local.sh

# build only, no push (no AWS needed)
SKIP_DEPLOY=true ./deploy/deploy-local.sh

# non-default profile
AWS_PROFILE=idptools ./deploy/deploy-local.sh
```

`DEPLOY_ENV` (prod | test) selects the bucket / distribution / config in
`entrypoint.sh`:

| DEPLOY_ENV | Bucket | Distribution | Config |
|---|---|---|---|
| `prod` (default) | `www.idptools.com` | `E1C72FI2JLYGWW` | `./env/prod.js` |
| `test` | `test.idptools.com` | `E21A46XVWQ32FG` | `./env/test-idptools-com.js` |

Overridable env vars: `S3_BUCKET`, `CLOUDFRONT_DISTRIBUTION_ID`, `AWS_REGION`,
`CONFIG_FILE`, `SKIP_DEPLOY`, `AWS_PROFILE`, `IMAGE_NAME`.

## GitHub Actions

Two workflows build the same image and run it, using the same two repo
**secrets** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`):

- `.github/workflows/website-deploy.yml` — **prod**, on push to `master` (`DEPLOY_ENV=prod`)
- `.github/workflows/website-deploy-test.yml` — **test**, on push to `develop` or manual dispatch (`DEPLOY_ENV=test`)

> These are stored as GitHub Actions secrets, never in the repo — safe for a
> public repository. A more secure alternative is GitHub OIDC federation (no
> long-lived keys); see the note below.

## Notes

- **No `--acl public-read`**: the content bucket uses `BucketOwnerEnforced`
  (ACLs disabled); public read comes from the bucket policy. This differs from
  the iyasec `jekyll.yml`, whose bucket had ACLs enabled.
- **`config`**: `CONFIG_FILE=./env/prod.js` (`client/src/env/prod.js`) points at
  `https://idptools.com`. There is no api backend in the static deployment, so
  token calls must be made client-side.
- **Supersedes** the reference `.github/workflows/jekyll.yml` copy in this repo
  (which still targets iyasec's distribution). Remove that file so it doesn't
  run.
- **More secure CI (optional)**: replace the two secrets with GitHub OIDC —
  configure an IAM role trusting `token.actions.githubusercontent.com`, add
  `permissions: id-token: write`, use `aws-actions/configure-aws-credentials`
  to assume the role, and pass the resulting env creds into `docker run`.
