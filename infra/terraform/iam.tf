# ---------------------------------------------------------------------------
# CI/CD deploy role for GitHub Actions (OIDC).
#
# Lets the GitHub Actions workflow assume a least-privilege role — no static
# access keys — to build/deploy the idptools.com and test.idptools.com sites
# and manage their TLS certificates.
#
# Permissions are scoped to just these two sites:
#   - S3     : full read/write on the four site buckets (prod + test content/logs)
#   - Route53: manage records in the shared idptools.com hosted zone (covers
#              apex, www, and test.idptools.com) — for DNS + ACM DNS validation
#   - ACM    : request/describe/delete/renew certificates in us-east-1
#              (CloudFront certs) and us-west-2 (regional)
#   - CloudFront: read/write (a global service; its actions do not support
#                 resource-level ARNs, so it is action-scoped on "*")
# ---------------------------------------------------------------------------

locals {
  # The four S3 buckets backing both sites, derived from var.domain (idptools.com):
  #   www.idptools.com / idptools-com-logs        (prod content / logs)
  #   test.idptools.com / test-idptools-com-logs  (test content / logs)
  deploy_bucket_names = [
    local.content_bucket_name,                    # prod content  (www.idptools.com)
    local.logs_bucket_name,                       # prod logs     (idptools-com-logs)
    "test.${var.domain}",                         # test content  (test.idptools.com)
    "test-${replace(var.domain, ".", "-")}-logs", # test logs     (test-idptools-com-logs)
  ]
  deploy_bucket_arns = [for b in local.deploy_bucket_names : "arn:aws:s3:::${b}"]
  deploy_object_arns = [for b in local.deploy_bucket_names : "arn:aws:s3:::${b}/*"]

  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

# GitHub Actions OIDC provider — one per AWS account. Create it here, or set
# create_github_oidc_provider = false to reuse one already in the account.
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS no longer validates this thumbprint for the GitHub host (it uses a
  # trusted CA store), but the API still requires the field. These are GitHub's
  # published values.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

# Trust policy: only the GitHub OIDC identity for the allowed repo/refs may
# assume the role, and only with the sts.amazonaws.com audience.
data "aws_iam_policy_document" "deploy_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.github_subject_claims
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = var.deploy_role_name
  description          = "GitHub Actions OIDC deploy role for ${var.domain} + test.${var.domain} (S3/CloudFront/Route53/ACM)."
  assume_role_policy   = data.aws_iam_policy_document.deploy_assume.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "deploy" {
  # --- S3: full read/write on just the two sites' content + logs buckets ---
  statement {
    sid       = "S3SiteBuckets"
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = concat(local.deploy_bucket_arns, local.deploy_object_arns)
  }

  # ListAllMyBuckets / GetBucketLocation are not resource-scopable; tooling
  # (aws cli / terraform) uses them for discovery.
  statement {
    sid       = "S3ListLocate"
    effect    = "Allow"
    actions   = ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]
    resources = ["*"]
  }

  # --- CloudFront: read/write. Global service; actions have no resource-level
  #     ARNs, so this is action-scoped on "*". ---
  statement {
    sid       = "CloudFront"
    effect    = "Allow"
    actions   = ["cloudfront:*"]
    resources = ["*"]
  }

  # --- Route 53: manage records in the shared idptools.com hosted zone
  #     (apex, www, and test.idptools.com) for DNS + ACM DNS validation. ---
  statement {
    sid    = "Route53Zone"
    effect = "Allow"
    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:ListResourceRecordSets",
      "route53:GetHostedZone",
      "route53:ListTagsForResource",
    ]
    resources = [aws_route53_zone.this.arn]
  }

  # Zone discovery + change-status polling are not resource-scopable.
  statement {
    sid    = "Route53Global"
    effect = "Allow"
    actions = [
      "route53:ListHostedZones",
      "route53:ListHostedZonesByName",
      "route53:GetChange",
    ]
    resources = ["*"]
  }

  # --- ACM: certificate generation + renewal. Cert ARNs are created by this
  #     role (dynamic), so resource is "*", constrained to the regions used:
  #     us-east-1 (CloudFront certs) and us-west-2 (regional). ---
  statement {
    sid    = "ACM"
    effect = "Allow"
    actions = [
      "acm:RequestCertificate",
      "acm:DeleteCertificate",
      "acm:DescribeCertificate",
      "acm:GetCertificate",
      "acm:ListCertificates",
      "acm:ListTagsForCertificate",
      "acm:AddTagsToCertificate",
      "acm:RemoveTagsFromCertificate",
      "acm:RenewCertificate",
      "acm:ResendValidationEmail",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["us-east-1", "us-west-2"]
    }
  }
}

resource "aws_iam_policy" "deploy" {
  name        = "${var.deploy_role_name}-policy"
  description = "Least-privilege deploy/manage permissions for the idptools.com sites (S3/CloudFront/Route53/ACM)."
  policy      = data.aws_iam_policy_document.deploy.json
}

resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}
