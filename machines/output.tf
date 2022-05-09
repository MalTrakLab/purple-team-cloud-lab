
output "dc_public_ip" {
  value       = aws_instance.adlab-dc.public_ip
  description = "The public IP of the ADLab DC EC2 machine"
}

output "win10_public_ip" {
  value       = aws_instance.adlab-win10.public_ip
  description = "The public IP of the ADLab Win10 EC2 machine"
}

output "blueteam_public_ip" {
  value       = aws_instance.blueteam-helk.public_ip
  description = "The public IP of the Blue Team HELK EC2 machine"
}

output "redteam_public_ip" {
  value       = aws_instance.redteam-caldera.public_ip
  description = "The public IP of the Red Team EC2 machine"
}
