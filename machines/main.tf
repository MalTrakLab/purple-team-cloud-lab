
resource "aws_security_group" "adlab-ingress-all" {
  name = "adlab-allow-all"
  vpc_id = var.vpc_id

  #Kerberos Key Distribution Center
  ingress {
    from_port   = 88
    to_port     = 88
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #Remote Procedure Call
  ingress {
    from_port   = 135
    to_port     = 135
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #NetBIOS Session Service
  ingress {
    from_port   = 139
    to_port     = 139
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #LDAP
  ingress {
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #SMB & Net Logon
  ingress {
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #WinRM/Powershell Remoting Access
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #Remote Desktop Access
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #Randomly Allocated Ports (Could be disabled)
  ingress {
    from_port   = 49152
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #DNS
  ingress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  
  #LDAP, DC Locator and also Net Logon
  ingress {
    from_port   = 389
    to_port     = 389
    protocol    = "udp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #Ping ICMP Packets
  ingress {
    from_port   = 8
    to_port     = 0
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Terraform removes the default rule
  egress {
   from_port = 0
   to_port = 0
   protocol = "-1"
   cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "blueteam-ingress-all" {
  name = "allow-all-sg"
  vpc_id = var.vpc_id
  #SSH
  ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
  }

  #helk-ksql-server
  ingress {
    from_port   = 8088
    to_port     = 8088
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #helk-kafka
  ingress {
    from_port   = 9092
    to_port     = 9093
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #helk-kafka-broker
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #helk-nginx
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #helk-nginx-ssl
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #helk-logstash
  ingress {
    from_port   = 3515
    to_port     = 3515
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  ingress {
    from_port   = 5044
    to_port     = 5044
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  ingress {
    from_port   = 8531
    to_port     = 8531
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }
  ingress {
    from_port   = 9600
    to_port     = 9600
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #helk-kibana
  ingress {
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }

  #helk-elasticsearch
  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 9300
    to_port     = 9300
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #RDP Protocol
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["${var.subnet_cidr_prefix}.0/24"]
  }


  # Terraform removes the default rule
  egress {
   from_port = 0
   to_port = 0
   protocol = "-1"
   cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "redteam-ingress-all" {
  name = "caldera-allow-all-sg"
  vpc_id = var.vpc_id
  ingress {
      cidr_blocks = [
        "0.0.0.0/0"
      ]
      from_port = 0
      to_port = 8888
      protocol = "tcp"
  }
  # Terraform removes the default rule
  egress {
   from_port = 0
   to_port = 0
   protocol = "-1"
   cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "adlab-dc" {
  ami           = "ami-03498572c21a9e8af"
  instance_type = "t2.micro"
  key_name = "ec2_key_pair"
  security_groups = [aws_security_group.adlab-ingress-all.id]
  private_ip = "${var.subnet_cidr_prefix}.100"
  subnet_id = var.subnet_id
  user_data = <<EOF
                <powershell>
                #Install Active Directory
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop -Confirm:$false

                #Enable WinRM
                Enable-PSRemoting –force
                Set-Service WinRM -StartMode Automatic
                Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString ${var.default_password} -AsPlainText -Force) -PasswordNeverExpires $true

                #Enable WinRM over HTTPS (always needed for untrusted hosts)
                $Cert = New-SelfSignedCertificate -DnsName "${var.adlab_domain}" -CertStoreLocation Cert:\LocalMachine\My
                $cmd = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname=`"${var.adlab_domain}`"; CertificateThumbprint=`"" + $Cert.Thumbprint + "`"}'"
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/service/auth @{basic="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/service @{AllowUnencrypted="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/client/auth @{basic="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/client @{AllowUnencrypted="true"}'
                Invoke-Expression $cmd
                netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5985
                netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5986
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
                </powershell>
            EOF
  root_block_device {
    delete_on_termination = true
    volume_size           = 30
  }

  tags = {
    Name = "Domain Controller EC2 Machine - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
  
  credit_specification {
    cpu_credits = "standard"
  }

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
  
  provisioner "local-exec" {
    command = "powershell.exe -ExecutionPolicy Unrestricted -Command ${path.module}\\Setup-AD.ps1 ${aws_instance.adlab-dc.public_ip}"
  }
}

resource "aws_instance" "adlab-win10" {
  ami           = "ami-03498572c21a9e8af"
  instance_type = "t2.micro"
  key_name = "ec2_key_pair"
  security_groups = [aws_security_group.adlab-ingress-all.id]
  private_ip = "${var.subnet_cidr_prefix}.110"
  subnet_id = var.subnet_id
  user_data = <<EOF
                <powershell>
                #Install Active Directory
                Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop -Confirm:$false

                #Enable WinRM
                Enable-PSRemoting –force
                Set-Service WinRM -StartMode Automatic
                Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString ${var.default_password} -AsPlainText -Force) -PasswordNeverExpires $true

                #Enable WinRM over HTTPS (always needed for untrusted hosts)
                $Cert = New-SelfSignedCertificate -DnsName "${var.adlab_domain}" -CertStoreLocation Cert:\LocalMachine\My
                $cmd = "winrm create winrm/config/Listener?Address=*+Transport=HTTPS '@{Hostname=`"${var.adlab_domain}`"; CertificateThumbprint=`"" + $Cert.Thumbprint + "`"}'"
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/service/auth @{basic="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/service @{AllowUnencrypted="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/client/auth @{basic="true"}'
                Invoke-Expression $cmd
                $cmd = 'winrm set winrm/config/client @{AllowUnencrypted="true"}'
                Invoke-Expression $cmd
                netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5985
                netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5986
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force
                </powershell>
            EOF
  root_block_device {
    delete_on_termination = true
    volume_size           = 30
  }

  tags = {
    Name = "Windows 10 Simple EC2 Machine - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
  
  credit_specification {
    cpu_credits = "standard"
  }

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }

  provisioner "local-exec" {
    command = "powershell.exe -ExecutionPolicy Unrestricted -Command ${path.module}\\Setup-Workstation.ps1 ${aws_instance.adlab-win10.public_ip}"
  }
  depends_on = [aws_instance.adlab-dc]
}

resource "aws_instance" "blueteam-helk" {
  ami           = "ami-0ffea00000f287d30"
  instance_type = "t2.large"
  key_name = var.key_name
  security_groups = [aws_security_group.blueteam-ingress-all.id]
  private_ip = "${var.blueteam_subnet_cidr_prefix}.100"
  subnet_id = var.blueteam_subnet_id
  user_data = file("${path.module}/blueteam-machine-config.yml")
  root_block_device {
    delete_on_termination = true
    volume_size           = 60
  }

  tags = {
    Name = "Blue Team HELK Machine - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
  
  credit_specification {
    cpu_credits = "standard"
  }

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
  depends_on = [aws_instance.adlab-dc]
}

resource "aws_instance" "redteam-caldera" {
  ami           = "ami-0ffea00000f287d30"
  instance_type = "t2.micro"
  key_name = "ec2_key_pair"
  security_groups = [aws_security_group.redteam-ingress-all.id]
  private_ip = "${var.attacker_subnet_cidr_prefix}.100"
  subnet_id = var.attacker_subnet_id
  user_data = file("${path.module}/redteam-machine-config.yml")

  root_block_device {
    delete_on_termination = true
    volume_size           = 20
  }

  tags = {
    Name = "Red Team Caldera Machine - ${var.env}"
    Workspace = "ADLab"
    Environment = var.env
  }
  
  credit_specification {
    cpu_credits = "standard"
  }

  lifecycle {
    ignore_changes = [
      security_groups,
    ]
  }
}
