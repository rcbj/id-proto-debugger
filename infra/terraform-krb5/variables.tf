variable "aws_region" {
  description = "Region for the VPC, the instance and the artifacts bucket."
  type        = string
  default     = "us-west-2"
}

variable "aws_profile" {
  description = "Optional named AWS CLI profile. Empty = default credential chain."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Who may reach the KDC.
#
# There is no default on purpose. The test speaks Kerberos to this instance from
# whatever machine runs the suite, so the address is a property of the RUN and
# not of the configuration — and a default here would be either useless or, if
# it were something like 0.0.0.0/0, an unauthenticated KDC on the public
# internet. infra/terraform-local.sh resolves it and passes it in.
# ---------------------------------------------------------------------------
variable "allowed_cidr" {
  description = "The ONE CIDR permitted to reach the KDC (e.g. 203.0.113.4/32). Required."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.allowed_cidr))
    error_message = "allowed_cidr must be valid CIDR notation, e.g. 203.0.113.4/32."
  }

  validation {
    condition     = !can(regex("^0\\.0\\.0\\.0/0$", var.allowed_cidr))
    error_message = "allowed_cidr must not be 0.0.0.0/0: that publishes a domain controller to the internet."
  }
}

variable "instance_type" {
  description = <<-EOT
    Instance type for the domain controller.

    Free tier is t2.micro/t3.micro, both 1 GiB, and the AWS Windows Server 2025
    AMI is the Desktop Experience image whose documented floor is 2 GB BEFORE the
    AD DS role is added. Promoting a forest on 1 GiB stalls, and a stalled KDC
    looks exactly like a Kerberos timeout — which is the thing the test measures,
    so the failure is worse than useless. t3.medium is the smallest size this has
    been made to work on; the cost is a few cents for the life of one run.
  EOT
  type        = string
  default     = "t3.medium"
}

variable "root_volume_gb" {
  description = "Root EBS size. The Windows Server 2025 AMI snapshot is 30 GiB, which is the floor."
  type        = number
  default     = 30
}

variable "enable_rdp" {
  description = "Also open 3389/tcp to allowed_cidr. Off by default — the build is driven by SSM Run Command, so RDP is for debugging by hand only."
  type        = bool
  default     = false
}

# ---------------------------------------------------------------------------
# The domain.
#
# `.local` rather than a real, resolvable suffix: this forest exists for the
# length of one test run and must never be mistaken for, or collide with,
# anything routable. The realm is the DNS name upper-cased, which is the
# convention the Kerberos code under test assumes.
# ---------------------------------------------------------------------------
variable "domain_name" {
  description = "AD DS DNS domain. The Kerberos realm is this, upper-cased."
  type        = string
  default     = "krb5test.local"
}

variable "netbios_name" {
  description = "NetBIOS domain name. 15 characters maximum, upper case."
  type        = string
  default     = "KRB5TEST"

  validation {
    condition     = length(var.netbios_name) <= 15 && upper(var.netbios_name) == var.netbios_name
    error_message = "netbios_name must be upper case and at most 15 characters."
  }
}

variable "test_user" {
  description = "The NON-ADMIN domain user the test authenticates as. Domain Users only; deliberately not in any privileged group, because a test that authenticates as an administrator proves less."
  type        = string
  default     = "kuser"
}

variable "service_account" {
  description = "Account the target service runs as, and the account the SPN is mapped to."
  type        = string
  default     = "svc-http"
}

variable "service_class" {
  description = "SPN service class. HTTP is what a Negotiate-protected web service uses."
  type        = string
  default     = "HTTP"
}

variable "service_host" {
  description = "Host portion of the SPN. Resolved inside the domain only; the test is given the SPN as a string and never resolves it."
  type        = string
  default     = "target"
}

variable "tags" {
  description = "Tags applied to every resource in this stack. The Stack tag is what makes the whole thing findable and is what the teardown check greps for."
  type        = map(string)
  default = {
    Project     = "oauth2-oidc-debugger"
    Stack       = "krb5-interop"
    Environment = "ephemeral"
    ManagedBy   = "terraform"
    Lifecycle   = "destroy-after-test-run"
  }
}

# ---------------------------------------------------------------------------
# The delegation fixture.
#
# Four accounts, and they mirror the mock KDC's four exactly
# (sts/krb5_principals.js) so that ONE test can drive either KDC with nothing
# but the realm differing. The roles are what matter, not the names:
#
#   frontend   classic constrained delegation: msDS-AllowedToDelegateTo names
#              the back-end, AND TrustedToAuthForDelegation so its S4U2Self
#              ticket comes back FORWARDABLE (the protocol-transition half).
#   backend    the classic target. Authorizes nothing itself.
#   notrusted  the same classic list as frontend MINUS protocol transition.
#              It exists because that flag's absence is invisible where it is
#              set: S4U2Self still succeeds and returns a ticket that simply is
#              not forwardable, and classic S4U2Proxy then fails a step later
#              complaining about the evidence. Two accounts differing in exactly
#              one attribute is the only way to show which attribute did it.
#   rbcd       resource-based target: msDS-AllowedToActOnBehalfOfOtherIdentity
#              names the front-end. The permission lives on the TARGET, which is
#              the inversion that is the whole security story of RBCD.
# ---------------------------------------------------------------------------
variable "provision_delegation" {
  description = "Create the four delegation accounts. Off makes the bootstrap shorter when only the AS/TGS/AP chain is wanted."
  type        = bool
  default     = true
}

variable "delegation_hosts" {
  description = "Host portions of the four delegation SPNs, keyed by role. The SPN is <service_class>/<host>.<domain_name>."
  type = object({
    frontend  = string
    backend   = string
    notrusted = string
    rbcd      = string
  })
  default = {
    frontend  = "frontend"
    backend   = "backend"
    notrusted = "notrusted"
    rbcd      = "rbcd"
  }
}
