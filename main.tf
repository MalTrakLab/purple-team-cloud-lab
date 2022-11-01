terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = ">= 3.35.0"
    }
  }
}

provider "aws" {
  region  = "eu-west-1"

}

#Creating our main VPC and subnets
module "adlab_network" {
    source = "./networks"
    env = "lab"
    cidr_prefix = "192.168"
}

#Creating our Lab Machines
module "AD" {
    source = "./machines"
    env = "lab"
    subnet_cidr_prefix = module.adlab_network.adlab_subnet_cidr_prefix
    blueteam_subnet_cidr_prefix = module.adlab_network.blueteam_subnet_cidr_prefix
    attacker_subnet_cidr_prefix = module.adlab_network.attacker_subnet_cidr_prefix
    vpc_id = module.adlab_network.adlab_vpc
    subnet_id = module.adlab_network.adlab_subnet
    blueteam_subnet_id = module.adlab_network.blueteam_subnet
    attacker_subnet_id = module.adlab_network.attacker_subnet
    key_name = "ec2_key_pair"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

output "adlab_dc_public_ip" {
    value = module.AD.dc_public_ip
} 

output "adlab_win10_public_ip" {
    value = module.AD.win10_public_ip
} 

output "blueteam_public_ip" {
  value       = module.AD.blueteam_public_ip
}

output "redteam_public_ip" {
  value       = module.AD.redteam_public_ip
}