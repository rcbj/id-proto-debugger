# ---------------------------------------------------------------------------
# What may reach the domain controller.
#
# Kerberos only, from one address. Note what is NOT here: no WinRM (5985/5986),
# and RDP only if explicitly asked for. The instance is built and interrogated
# through SSM Run Command, which is an OUTBOUND connection from the agent to the
# SSM endpoints — so the management path needs no inbound rule at all. That is
# the reason this group can be as small as it is.
#
# 88 is opened on BOTH tcp and udp because a KDC answers on both and the
# client's choice between them is part of what the test exercises: a KDC-REP
# carrying a PAC usually exceeds the UDP threshold, so the exchange falls back to
# TCP, and a run where only one transport is reachable would hide that.
# ---------------------------------------------------------------------------
resource "aws_security_group" "dc" {
  name        = "${local.name_prefix}-dc"
  description = "Kerberos from one address only; egress open for SSM, S3 and Windows Update."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-dc" }

  # Replacing this group means detaching it from a running instance, which AWS
  # will not do while it is in use. Create the replacement first.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "kerberos_tcp" {
  security_group_id = aws_security_group.dc.id
  description       = "Kerberos KDC (TCP) from the test runner only"
  cidr_ipv4         = var.allowed_cidr
  from_port         = 88
  to_port           = 88
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "kerberos_udp" {
  security_group_id = aws_security_group.dc.id
  description       = "Kerberos KDC (UDP) from the test runner only"
  cidr_ipv4         = var.allowed_cidr
  from_port         = 88
  to_port           = 88
  ip_protocol       = "udp"
}

# Off by default. Kept because when a forest promotion goes wrong the console
# screenshot is rarely enough, and the alternative is rebuilding blind.
resource "aws_vpc_security_group_ingress_rule" "rdp" {
  count = var.enable_rdp ? 1 : 0

  security_group_id = aws_security_group.dc.id
  description       = "RDP from the test runner only (debugging)"
  cidr_ipv4         = var.allowed_cidr
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
}

# Egress has to be open: the agent reaches SSM, the bootstrap writes the keytab
# to S3, and ktpass is only available once the AD DS tools are installed.
resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.dc.id
  description       = "All egress (SSM, S3, Windows Update)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
