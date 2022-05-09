resource "aws_vpc" "adlab_vpc" {
  cidr_block = "${var.cidr_prefix}.0.0/16"
  tags = {
    Name = "ADLAB VPC"
    Workspace = "ADLab"
  }
}

resource "aws_internet_gateway" "adlab_gw" {
  vpc_id = aws_vpc.adlab_vpc.id
  tags = {
    Name = "ADLAB Default Gateway - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
}

resource "aws_subnet" "adlab_subnet" {
  vpc_id            = aws_vpc.adlab_vpc.id
  cidr_block        = "${var.cidr_prefix}.10.0/24"
  availability_zone = "eu-west-1a"
  map_public_ip_on_launch = true
  depends_on = [aws_internet_gateway.adlab_gw]

  tags = {
    Name = "Main ADLAB Subnet - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
}

resource "aws_subnet" "blueteam_subnet" {
  vpc_id            = aws_vpc.adlab_vpc.id
  cidr_block        = "${var.cidr_prefix}.20.0/24"
  availability_zone = "eu-west-1a"
  map_public_ip_on_launch = true
  depends_on = [aws_internet_gateway.adlab_gw]

  tags = {
    Name = "blueteam ADLAB Subnet - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
}

resource "aws_subnet" "attacker_subnet" {
  vpc_id            = aws_vpc.adlab_vpc.id
  cidr_block        = "${var.cidr_prefix}.30.0/24"
  availability_zone = "eu-west-1a"
  map_public_ip_on_launch = true
  depends_on = [aws_internet_gateway.adlab_gw]

  tags = {
    Name = "Attacker ADLAB Subnet - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
}

resource "aws_route_table" "adlab-route-table" {
  vpc_id = aws_vpc.adlab_vpc.id
  route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.adlab_gw.id
  }
  tags = {
    Name = "adlab-route-table"
    Workplace = "ADLab"
    Environment = var.env
  }
}

resource "aws_route_table_association" "adlab-subnet-association" {
  subnet_id      = aws_subnet.adlab_subnet.id
  route_table_id = aws_route_table.adlab-route-table.id
}

resource "aws_route_table_association" "blueteam-subnet-association" {
  subnet_id      = aws_subnet.blueteam_subnet.id
  route_table_id = aws_route_table.adlab-route-table.id
}

resource "aws_route_table_association" "attacker-subnet-association" {
  subnet_id      = aws_subnet.attacker_subnet.id
  route_table_id = aws_route_table.adlab-route-table.id
}

