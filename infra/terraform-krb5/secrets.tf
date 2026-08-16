# ---------------------------------------------------------------------------
# Passwords and the instance key.
#
# All generated per apply. Nothing is committed and nothing is read from disk;
# they exist in the (encrypted, private) state file and in the outputs, which is
# the right place for a credential whose whole life is one test run.
#
# `override_special` is narrowed on purpose. These strings are interpolated into
# a PowerShell script and passed to ktpass and net user, and the default special
# set includes the characters that break exactly that: $ expands a variable, a
# backtick escapes, and a quote or backslash ends or mangles the argument. The
# excluded characters buy nothing here — length does the work instead.
# ---------------------------------------------------------------------------
locals {
  pw_special = "!@#%^*-_=+"
}

# The forest's Administrator / DSRM password.
resource "random_password" "admin" {
  length           = 24
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = local.pw_special
}

# The non-admin user the test authenticates AS.
resource "random_password" "test_user" {
  length           = 24
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = local.pw_special
}

# The service account the SPN maps to. ktpass sets this password and derives the
# keytab key from it, so the two are the same secret by construction.
resource "random_password" "service" {
  length           = 24
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = local.pw_special
}

# ---------------------------------------------------------------------------
# The instance key pair. Windows does not take an SSH key for login: EC2
# encrypts the generated Administrator password with the PUBLIC half, and
# `aws ec2 get-password-data` needs the PRIVATE half to read it back. That is the
# only reason this exists — the bootstrap sets its own Administrator password
# anyway, so this is a fallback for hand debugging over RDP.
# ---------------------------------------------------------------------------
resource "tls_private_key" "dc" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "dc" {
  key_name   = "${local.name_prefix}-dc"
  public_key = tls_private_key.dc.public_key_openssh
  tags       = { Name = "${local.name_prefix}-dc" }
}
