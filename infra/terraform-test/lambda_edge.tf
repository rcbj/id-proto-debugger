# --- Lambda@Edge: the landings that receive an IdP's POST --------------------
#
# The static site has no server, and two protocols return their result as an
# HTTP POST from the IdP:
#
#   /wsfed              WS-Federation  — the Passive Requestor Profile's wresult
#   /samlacs, /samlslo  SAML 2.0       — the Response / LogoutResponse
#
# S3 answers a POST with 405/403, so both are answered here instead. The two
# cases differ in how badly they need it:
#
#   * WS-Federation has NO alternative. The passive profile defines exactly one
#     way to return the token and there is no redirect response binding to ask
#     for, so without this the round trip cannot complete on static hosting.
#   * SAML has one, and the debugger used it: with no landing it asks the IdP to
#     return the Response over HTTP-Redirect to a static page. That works, but
#     saml-profiles-2.0-os section 4.1.2 says the Redirect binding MUST NOT carry
#     the Response "as the response will typically exceed the URL length
#     permitted by most user agents" — and an ENCRYPTED assertion is exactly that
#     case, since ciphertext does not compress. With this landing the static
#     sites use POST like everyone else. The Redirect path is kept as the
#     fallback for a deployment without the Lambda.
#
# Both are deliberately Lambda@Edge and not CloudFront Functions like the sibling
# callback_rewrite: CloudFront Functions are never given the request body, so the
# token would be gone before any code could read it. Only Lambda@Edge with
# include_body = true on viewer-request receives it.
#
# The handlers are shared verbatim by both stacks (infra/edge/ — one
# implementation, one per-environment deployment) and share edge_common.js, which
# is why the zip is built from the whole directory rather than a single file.
# Lambda@Edge forbids environment variables, so everything they need is baked in.
#
# Two operational notes:
#   * Lambda@Edge functions MUST live in us-east-1, whatever region the rest of
#     the stack uses; hence the provider alias on every resource here.
#   * CloudFront replicates them to the edge locations, and AWS deletes those
#     replicas on its own schedule. A `terraform destroy` shortly after an apply
#     will fail with "Lambda was unable to delete ... replicated function"; wait
#     (up to a few hours) and re-run. This is an AWS constraint, not a
#     configuration problem.

# One zip for both functions: they require ./edge_common.js, so the archive has
# to carry the directory. Each function selects its own entry point via `handler`.
data "archive_file" "edge_landings" {
  type        = "zip"
  source_dir  = "${path.module}/../edge"
  output_path = "${path.module}/.terraform-artifacts/edge_landings.zip"
}

data "aws_iam_policy_document" "edge_landing_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      # Both are required: lambda.amazonaws.com to create/invoke the function,
      # edgelambda.amazonaws.com for CloudFront to run the replicas.
      identifiers = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "edge_landing" {
  provider           = aws.us_east_1
  name               = "${replace(var.domain, ".", "-")}-edge-landing"
  description        = "Execution role for the Lambda@Edge IdP-response landings on ${var.domain}"
  assume_role_policy = data.aws_iam_policy_document.edge_landing_assume.json
}

# CloudWatch Logs only. These functions read a form body and return a page; they
# touch no AWS resource. Note the logs land in the region nearest the viewer, not
# in us-east-1 — that is where to look when debugging a live sign-in.
resource "aws_iam_role_policy_attachment" "edge_landing_logs" {
  provider   = aws.us_east_1
  role       = aws_iam_role.edge_landing.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda@Edge viewer-request limits: 5 s timeout, 128 MB memory — both the
# maximum allowed for this event type, not a guess. `publish` is required because
# a cache behavior can only reference a published version, never $LATEST;
# qualified_arn is that version's ARN.
resource "aws_lambda_function" "wsfed_landing" {
  provider         = aws.us_east_1
  function_name    = "${replace(var.domain, ".", "-")}-wsfed-landing"
  description      = "WS-Federation Passive Requestor landing (captures the IdP's wresult POST) for ${var.domain}"
  role             = aws_iam_role.edge_landing.arn
  handler          = "wsfed_landing.handler"
  runtime          = "nodejs20.x"
  filename         = data.archive_file.edge_landings.output_path
  source_code_hash = data.archive_file.edge_landings.output_base64sha256
  timeout          = 5
  memory_size      = 128
  publish          = true
}

resource "aws_lambda_function" "saml_landing" {
  provider         = aws.us_east_1
  function_name    = "${replace(var.domain, ".", "-")}-saml-landing"
  description      = "SAML 2.0 ACS / SLO landing (captures the IdP's SAMLResponse POST) for ${var.domain}"
  role             = aws_iam_role.edge_landing.arn
  handler          = "saml_landing.handler"
  runtime          = "nodejs20.x"
  filename         = data.archive_file.edge_landings.output_path
  source_code_hash = data.archive_file.edge_landings.output_base64sha256
  timeout          = 5
  memory_size      = 128
  publish          = true
}
