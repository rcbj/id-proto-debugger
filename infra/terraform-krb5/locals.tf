locals {
  # Everything this stack creates carries this prefix, so a stray resource is
  # identifiable by name alone and not only by tag.
  name_prefix = "krb5-interop"

  # The Kerberos realm is the DNS domain upper-cased. Written once, here, because
  # the userdata, the outputs and the test all have to agree on it.
  realm = upper(var.domain_name)

  # The service principal name the test asks the KDC for a ticket to.
  service_fqdn = "${var.service_host}.${var.domain_name}"
  spn          = "${var.service_class}/${local.service_fqdn}"

  # A /24 of its own. The address range does not matter and nothing peers with
  # it; what matters is that it is this module's VPC and not the account's
  # default one, so destroying this stack cannot disturb anything else.
  vpc_cidr    = "10.242.0.0/16"
  subnet_cidr = "10.242.1.0/24"

  # The VPC resolver, which is always the VPC CIDR base plus two. Promoting a
  # domain controller repoints the box's DNS at itself, and without this address
  # as a forwarder it can no longer resolve anything outside the forest — which
  # takes SSM offline and with it the only channel into the instance. See the
  # note in userdata.ps1.tftpl.
  vpc_dns = cidrhost(local.vpc_cidr, 2)

  # The delegation fixture, resolved once so the userdata, the outputs and the
  # test cannot disagree about a single SPN. sAMAccountName is capped at 20
  # characters by AD, which "svc-notrusted" (13) is comfortably inside.
  delegation = {
    for role, host in var.delegation_hosts : role => {
      account = "svc-${host}"
      spn     = "${var.service_class}/${host}.${var.domain_name}"
    }
  }
}
