# ---------------------------------------------------------------------------
# The instance's own role. Nothing here is shared with the site stacks: the role,
# the policy and the profile all carry this stack's prefix and all live in this
# stack's state, so destroying it removes them and touches no other role.
#
# Two permissions, and no more than two:
#
#   * AmazonSSMManagedInstanceCore, so the agent can register and Run Command
#     works. This is what removes the need for any inbound management port.
#   * PutObject on ONE prefix of ONE bucket, so the bootstrap can hand back the
#     keytab and its status. Not s3:* and not a wildcard resource — the
#     instance's credentials are reachable by anything running on it, and a
#     domain controller built by a script is not a place to keep broad rights.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dc" {
  name               = "${local.name_prefix}-dc"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = { Name = "${local.name_prefix}-dc" }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.dc.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "artifacts_write" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/bootstrap/*"]
  }
}

resource "aws_iam_role_policy" "artifacts_write" {
  name   = "${local.name_prefix}-artifacts-write"
  role   = aws_iam_role.dc.id
  policy = data.aws_iam_policy_document.artifacts_write.json
}

resource "aws_iam_instance_profile" "dc" {
  name = "${local.name_prefix}-dc"
  role = aws_iam_role.dc.name
  tags = { Name = "${local.name_prefix}-dc" }
}
