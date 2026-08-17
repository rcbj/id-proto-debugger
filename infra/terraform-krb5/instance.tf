# ---------------------------------------------------------------------------
# The domain controller.
#
# The AMI is resolved by filter rather than pinned: AWS republishes the Windows
# Server 2025 base image monthly and a pinned id goes stale, which surfaces as an
# InvalidAMIID.NotFound weeks later. most_recent with an owner filter of `amazon`
# is the trade — the exact image can move under a re-apply, which for a stack
# whose entire life is one test run is the right way round.
# ---------------------------------------------------------------------------
data "aws_ami" "windows_2025" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2025-English-Full-Base-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_instance" "dc" {
  ami                    = data.aws_ami.windows_2025.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.dc.id]
  iam_instance_profile   = aws_iam_instance_profile.dc.name
  key_name               = aws_key_pair.dc.key_name

  # The bootstrap writes to S3 through the instance profile, so the profile has
  # to be attached before the instance boots — which it is, but the dependency is
  # stated because Terraform will otherwise happily create them in parallel and
  # the userdata's first upload races the attachment.
  depends_on = [
    aws_iam_role_policy.artifacts_write,
    aws_iam_role_policy_attachment.ssm,
    aws_internet_gateway.main,
  ]

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  # IMDSv2 only. The instance profile's credentials are reachable from anything
  # running on the box, and this is a box that runs a script off the internet.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/userdata.ps1.tftpl", {
    domain_name        = var.domain_name
    netbios_name       = var.netbios_name
    realm              = local.realm
    admin_password     = random_password.admin.result
    test_user          = var.test_user
    test_user_password = random_password.test_user.result
    service_account    = var.service_account
    service_password   = random_password.service.result
    spn                = local.spn
    artifacts_bucket   = aws_s3_bucket.artifacts.bucket
    aws_region         = var.aws_region
    vpc_dns            = local.vpc_dns

    # The delegation fixture. Flattened to scalars rather than passed as an
    # object because templatefile() has no way to iterate a map inside a
    # PowerShell here-string without generating $${...}, which templatefile()
    # would then try to interpolate itself.
    provision_delegation         = var.provision_delegation
    delegation_password          = random_password.delegation.result
    delegation_frontend_account  = local.delegation.frontend.account
    delegation_frontend_spn      = local.delegation.frontend.spn
    delegation_backend_account   = local.delegation.backend.account
    delegation_backend_spn       = local.delegation.backend.spn
    delegation_notrusted_account = local.delegation.notrusted.account
    delegation_notrusted_spn     = local.delegation.notrusted.spn
    delegation_rbcd_account      = local.delegation.rbcd.account
    delegation_rbcd_spn          = local.delegation.rbcd.spn
  })

  # Re-rendering the userdata (a changed password, a changed SPN) has to rebuild
  # the instance: userdata runs once, at first boot, so an in-place change would
  # silently not happen.
  user_data_replace_on_change = true

  tags = {
    Name = "${local.name_prefix}-dc"
    Role = "kerberos-kdc"
  }
}
