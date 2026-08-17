# terraform-krb5 — an ephemeral Windows KDC

A single-DC Active Directory forest on one EC2 instance, so that
`tests/krb5_real_dc.js` can drive a **real Microsoft KDC** instead of the mock
one in the `rcbj/mock-sts` submodule. It exists for the length of one test run.

```
./infra/krb5-test.sh          # apply -> wait -> test -> destroy
KRB5_KEEP=1 ./infra/krb5-test.sh   # leave it up to debug
```

## Why it is a separate root module

Because it has to be destroyed routinely, and the static sites must not be
anywhere near that operation.

Terraform can only destroy what is in the state file it is pointed at. This
module writes to **`krb5-interop/dc.tfstate`**; the sites are at
`idptools.com/prod.tfstate` and `idptools.com/test.tfstate`. Those are three
different objects in the same bucket, and a `destroy` here cannot see — let alone
remove — a bucket, a distribution, a certificate or a Route 53 record belonging
to either site.

That separation is reinforced rather than merely asserted:

* **No shared resources.** This module creates its own VPC, subnet, internet
  gateway and route table rather than borrowing the account's default VPC. The
  default VPC is the one network object a site stack could plausibly come to
  depend on, so it is not used.
* **No cross-stack reads.** There is no `terraform_remote_state`, no data source
  looking up something another stack made, and no hard-coded ARN belonging to
  one. The only thing held in common with the site stacks is the state *bucket*,
  which Terraform never destroys.
* **Its own IAM.** A role, an inline policy and an instance profile, all prefixed
  `krb5-interop`, all in this state.
* **Its own bucket** for the bootstrap's artifacts, with `force_destroy = true`
  so teardown is not blocked by the objects the instance wrote.

Everything carries `Stack = "krb5-interop"` as well, so a leftover is findable by
tag if a destroy is ever interrupted.

## What it builds

| | |
|---|---|
| VPC / subnet / IGW / route table | `10.242.0.0/16`, one public `/24` |
| Security group | **88/tcp and 88/udp from one CIDR**, egress open. RDP only if `enable_rdp` |
| IAM role + instance profile | `AmazonSSMManagedInstanceCore`, plus `s3:PutObject` on one prefix |
| S3 bucket | private, encrypted, `force_destroy`; holds `dc.json` and `status.json` |
| EC2 instance | Windows Server 2025, `t3.medium`, IMDSv2 required, encrypted gp3 root |

The instance's UserData installs AD DS and promotes a forest, then a scheduled
task finishes the job after the reboot: it creates a **non-admin** domain user,
creates the service account, maps the SPN, runs `ktpass` to produce a keytab, and
uploads the keytab and a status marker to the bucket.

## Two things that will bite

**The instance type is not free tier, and that is deliberate.** Free tier is
`t2.micro`/`t3.micro`, both 1 GiB, and the Windows Server 2025 AMI is the Desktop
Experience image whose documented floor is 2 GB before AD DS is added. A forest
promotion on 1 GiB stalls, and a stalled KDC is indistinguishable from the
Kerberos timeout the test exists to detect — so the cheap option produces an
ambiguous result rather than a cheap one. `t3.medium` is about six cents an hour.

**DNS forwarding is load-bearing.** Promoting a domain controller repoints the
machine's resolver at itself, after which it can no longer resolve
`ssm.<region>.amazonaws.com` or `s3.<region>.amazonaws.com` — the SSM agent goes
offline and the bootstrap's upload fails, which between them remove every channel
into the instance. `stage2` therefore adds the VPC resolver
(`cidrhost(vpc_cidr, 2)`) as a forwarder before it does anything else. If you
change the network, keep that.

## If the bootstrap fails

`krb5-test.sh` prints the tail of `stage1.log` / `stage2.log` from the bucket and
then destroys the stack. To keep it up and look yourself:

```
KRB5_KEEP=1 ./infra/krb5-test.sh
aws ssm start-session --target "$(terraform output -raw instance_id)"
```

The instance is managed by SSM, so no inbound management port is open. For RDP,
set `enable_rdp = true` and read the password with `terraform output -raw
administrator_password`.

## Running Terraform directly

`allowed_cidr` has no default — it is the address of whatever machine runs the
test, which is a property of the run:

```
cd infra/terraform-krb5
terraform init
terraform apply -var "allowed_cidr=$(curl -s https://checkip.amazonaws.com)/32"
terraform destroy -var "allowed_cidr=0.0.0.0/32"   # value is unused on destroy
```

Or through the containerised runner, which resolves the address for you:

```
./infra/terraform-local.sh krb5 apply
./infra/terraform-local.sh krb5 destroy
```
