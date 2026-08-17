# ---------------------------------------------------------------------------
# A VPC of this stack's own, and that is a deliberate cost rather than laziness
# avoided.
#
# Borrowing the account's default VPC would be two fewer resources and would
# also be the one thing that could make `terraform destroy` here reach something
# the static sites care about — a shared subnet, a shared route table, a security
# group somebody else attached. Owning the network means the destroy is closed
# over exactly what this module created.
#
# There is no NAT gateway: the instance sits in a public subnet with a public IP,
# which is how it reaches Windows Update, SSM and S3. A NAT gateway would cost
# more per hour than the instance.
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block = local.vpc_cidr

  # Both are required for the SSM agent to resolve its endpoints, and DNS is not
  # optional for a domain controller.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.subnet_cidr
  map_public_ip_on_launch = true

  tags = { Name = "${local.name_prefix}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}
