output "adlab_vpc" {
  description = "The Main Analysis VPC"
  value       = aws_vpc.adlab_vpc.id
}

output "adlab_subnet" {
  description = "The Main Analysis Subnet"
  value = aws_subnet.adlab_subnet.id
}

output "blueteam_subnet" {
  description = "The Blue Team Subnet"
  value = aws_subnet.blueteam_subnet.id
}

output "attacker_subnet" {
  description = "The Red Team Subnet"
  value = aws_subnet.attacker_subnet.id
}
output "adlab_subnet_cidr_prefix" {
    description = "Subnet cidr"
    value = "${var.cidr_prefix}.10"
}

output "blueteam_subnet_cidr_prefix" {
    description = "Subnet cidr"
    value = "${var.cidr_prefix}.20"
}

output "attacker_subnet_cidr_prefix" {
    description = "Subnet cidr"
    value = "${var.cidr_prefix}.30"
}