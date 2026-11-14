# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

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

  # The Lambda@Edge landings (lambda_edge.tf), for BOTH sites — the same reason
  # the bucket list above covers both: this one policy is what the prod stack
  # (infra/terraform) and the test stack (infra/terraform-test) both deploy with,
  # and each stack owns its own copy of these resources.
  edge_landing_role_names = [
    "${replace(var.domain, ".", "-")}-edge-landing",      # idptools-com-edge-landing
    "test-${replace(var.domain, ".", "-")}-edge-landing", # test-idptools-com-edge-landing
  ]
  edge_landing_role_arns = [
    for r in local.edge_landing_role_names : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${r}"
  ]
  # Lambda@Edge functions live in us-east-1 by definition. Both the unqualified
  # ARN and the :version form are needed — `publish = true` means every apply
  # addresses a numbered version, and the unqualified ARN alone does not match it.
  edge_landing_function_names = [
    "${replace(var.domain, ".", "-")}-wsfed-landing",
    "${replace(var.domain, ".", "-")}-saml-landing",
    "test-${replace(var.domain, ".", "-")}-wsfed-landing",
    "test-${replace(var.domain, ".", "-")}-saml-landing",
  ]
  edge_landing_function_arns = concat(
    [for f in local.edge_landing_function_names : "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:${f}"],
    [for f in local.edge_landing_function_names : "arn:aws:lambda:us-east-1:${data.aws_caller_identity.current.account_id}:function:${f}:*"],
  )

  github_oidc_provider_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

data "aws_caller_identity" "current" {}

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

  # --- Lambda@Edge landings (lambda_edge.tf): the execution role -----------
  # Without these a plan cannot even refresh: the first symptom was
  # "AccessDenied: iam:GetRole on resource: role test-idptools-com-edge-landing".
  # The write actions are here too, because a policy that lets terraform read a
  # resource but not create or destroy it just moves the failure to apply time.
  statement {
    sid    = "EdgeLandingRole"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRoleDescription",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:ListRoleTags",
      "iam:ListAttachedRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      # terraform checks this before deleting a role.
      "iam:ListInstanceProfilesForRole",
    ]
    resources = local.edge_landing_role_arns
  }

  # Creating or updating either function hands that role to Lambda, which is a
  # PassRole. Conditioned on the service so it cannot be used to pass the role
  # anywhere else.
  statement {
    sid       = "EdgeLandingPassRole"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = local.edge_landing_role_arns

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
  }

  # --- Lambda@Edge landings: the two functions ----------------------------
  # EnableReplication/DisableReplication are the Lambda@Edge-specific pair:
  # CloudFront copies the function to the edge regions, and the caller
  # associating it needs them.
  statement {
    sid    = "EdgeLandingFunctions"
    effect = "Allow"
    actions = [
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:GetFunctionCodeSigningConfig",
      "lambda:CreateFunction",
      "lambda:DeleteFunction",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:PublishVersion",
      "lambda:ListVersionsByFunction",
      "lambda:GetPolicy",
      "lambda:AddPermission",
      "lambda:RemovePermission",
      "lambda:ListTags",
      "lambda:TagResource",
      "lambda:UntagResource",
      "lambda:EnableReplication",
      "lambda:DisableReplication",
    ]
    resources = local.edge_landing_function_arns
  }

  # --- This deploy identity's OWN role/policy/OIDC provider: READ ONLY -----
  # The prod stack manages these three (they are in prod.tfstate), so a plan has
  # to be able to refresh them or it fails the same way the edge role did.
  #
  # Read only, deliberately. Granting iam:CreatePolicyVersion on the very policy
  # that grants these permissions would let anything holding this identity's keys
  # rewrite its own permissions — the classic privilege-escalation shape, and not
  # something a CI deploy user should have. The consequence is that a change to
  # THIS policy cannot be applied by the workflow: it has to be published by an
  # administrator first (which is how this statement itself arrived), after which
  # terraform sees no diff and carries on.
  statement {
    sid    = "DeployIdentitySelfRead"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:ListRoleTags",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:ListEntitiesForPolicy",
      "iam:GetOpenIDConnectProvider",
    ]
    # Built from the names, NOT from aws_iam_policy.deploy.arn: that resource's
    # policy body IS this document, so referencing it here is a dependency cycle
    # (policy -> document -> policy). The names are fixed by var.deploy_role_name,
    # so the ARNs are known without reading the resources back.
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.deploy_role_name}",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/${var.deploy_role_name}-policy",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com",
    ]
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
