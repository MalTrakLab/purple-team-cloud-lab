variable "env" {
    type = string
    default = "dev"
}

variable "subnet_cidr_prefix" {
    type = string
    default = "192.168.10"
}

variable "blueteam_subnet_cidr_prefix" {
    type = string
    default = "192.168.20"
}

variable "attacker_subnet_cidr_prefix" {
    type = string
    default = "192.168.30"
}

variable "vpc_id" {
    type = string
}

variable "subnet_id" {
    type = string
}

variable "blueteam_subnet_id" {
    type = string
}

variable "attacker_subnet_id" {
    type = string
}

variable "default_password" {
    type = string
    default = "LabPass1"
}

variable "adlab_domain" {
    type = string
    default = "adlab.local"
}

variable "key_name" {
    type = string
    default = "ec2_key_pair"
}