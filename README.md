# Automate-Infrastructure-With-IAC-Using-Terraform-Part-2.

This is the continuation of Automate-Infrastructure-With-IAC-Using-Terraform-Part-1, where we have already created VPC and public subnets.

We continue by creating private subnet by entrying the code below in main.tf file.

    resource "aws_subnet" "private" {
     vpc_id     = aws_vpc.main.id
     count      = var.preferred_number_of_private_subnets == null ? length(data.aws_availability_zones.available.names) :      var.preferred_number_of_private_subnets
     cidr_block = cidrsubnet(var.vpc_cidr, 8, count.index + 2)

     tags = merge(
      var.tags,
     {
       Name = format("%s-PRIVATE-SUBNET-%s", var.name, count.index)
      },
    )
    }
    
    
Enter the values below in the variables.tf file.
    
    variable "preferred_number_of_private_subnets" {
     type        = number
     description = "Number of private subnets"
    }

    variable "name" {
     type    = string
     default = "ACS"
    }

    variable "tags" {
     type        = map(string)
     description = "A mapping of tags to assign to all resources"
     default     = {}
    }
     
     
Enter values below in terraform.tfvars file.
 
    preferred_number_of_private_subnets = 4

     tags = {
     Owner-Email = "oguneye.lami@gmail.com"
     Managed-By  = "Terraform"
     }
     
Since our vpc_cidr = "10.0.0.0/16", the newly created private cidr_blocks will be:

      10.0.2.0/24
      10.0.3.0/24
      10.0.4.0/24
      10.0.5.0/24
      
Our next task is to create a NatGateway, which is dependent on an Elastic IP. Similarly, the Elastic IP is dependent on the Internet Gateway. Therefore, we will produce separate files, namely internet-gw.tf for the Internet Gateway and nat-gw.tf for the NatGateway.


internet-gw.tf

         resource "aws_internet_gateway" "ig" {
           vpc_id = aws_vpc.main.id

           tags = merge(
            var.tags,
           {
             Name = format("%s-%s-%s!", var.name, aws_vpc.main.id, "IG")
           },
         )
       }
      
nat-gw.tf

    resource "aws_eip" "nat_eip" {
     vpc        = true
     depends_on = [aws_internet_gateway.ig]

     tags = merge(
      var.tags,
      {
         Name = format("%s-EIP-%s", var.name, var.environment)
       },
     )
    }

    #Create Nat-Gateway
     
     resource "aws_nat_gateway" "nat" {
        allocation_id = aws_eip.nat_eip.id
        subnet_id     = element(aws_subnet.public.*.id, 0)
        depends_on    = [aws_internet_gateway.ig]

        tags = merge(
         var.tags,
        {
          Name = format("%s-NAT-%s", var.name, var.environment)
        },
      )
     }
     
 
Add also to variables.tf
  
      variable "environment" {
      type        = string
      description = "Environment"
     }
     
     
Add code to terraform.tfvars
         environment = "PROD"
         
         
The next step is set up the aws_route_table, aws_route and aws_route_table_association

Create a file named routes.tf, which contains resource for aws_route_table, aws_routes and aws_route_table_association for both private and public subnets.

       #create private route table
       
        resource "aws_route_table" "private-rtb" {
          vpc_id = aws_vpc.main.id

          tags = merge(
           var.tags,
          {
            Name = format("%s-PRIVATE-ROUTE-TABLE-%s", var.name, var.environment)
           },
        )
      }


       #create route table for the public subnets

     resource "aws_route_table" "public-rtb" {
       vpc_id = aws_vpc.main.id

       tags = merge(
       var.tags,
       {
         Name = format("%s-PUBLIC-ROUTE-TABLE-%s", var.name, var.environment)
        },
      )
     }


     #associate all private subnets to the private route table

    resource "aws_route_table_association" "private-subnets-assoc" {
     count          = length(aws_subnet.private[*].id)
     subnet_id      = element(aws_subnet.private[*].id, count.index)
     route_table_id = aws_route_table.private-rtb.id
    }

    #associate all public subnets to the public route table

    resource "aws_route_table_association" "public-subnets-assoc" {
     count          = length(aws_subnet.public[*].id)
     subnet_id      = element(aws_subnet.public[*].id, count.index)
     route_table_id = aws_route_table.public-rtb.id
    }

    #create route for the private route table and attatch a nat gateway to it

    resource "aws_route" "private-rtb-route" {
     route_table_id         = aws_route_table.private-rtb.id
     destination_cidr_block = "0.0.0.0/0"
     gateway_id             = aws_nat_gateway.nat.id
    }


    #create route for the public route table and attach the internet gateway 

    resource "aws_route" "public-rtb-route" {
     route_table_id         = aws_route_table.public-rtb.id
     destination_cidr_block = "0.0.0.0/0"
     gateway_id             = aws_internet_gateway.ig.id
     }


Create certificate manager with the file cert.tf:

      #The entire section create a certiface, public zone, and validate the certificate using DNS method

      #Create the certificate using a wildcard for all the domains created in projectaws.xyz
        resource "aws_acm_certificate" "project_terraform_cert" {
          domain_name       = "*.projectaws.xyz"
          validation_method = "DNS"
         }

      #calling the hosted zone
       data "aws_route53_zone" "project_terraform_zone" {
       name         = "projectaws.xyz"
       private_zone = false
       }

      #validate the certificate through DNS method
       resource "aws_acm_certificate_validation" "project_terraform_validation" {
         certificate_arn         = aws_acm_certificate.project_terraform_cert.arn
         validation_record_fqdns = [for record in aws_route53_record.project_terraform_record : record.fqdn]
        }

       #selecting validation method
       resource "aws_route53_record" "project_terraform_record" {
         for_each = {
           for dvo in aws_acm_certificate.project_terraform_cert.domain_validation_options : dvo.domain_name => {
             name   = dvo.resource_record_name
             record = dvo.resource_record_value
             type   = dvo.resource_record_type
           }
         } 

        allow_overwrite = true
        name            = each.value.name
        records         = [each.value.record]
        ttl             = 60
        type            = each.value.type
        zone_id         = data.aws_route53_zone.project_terraform_zone.zone_id
      }



     #create records for tooling
      resource "aws_route53_record" "tooling" {
       zone_id = data.aws_route53_zone.project_terraform_zone.zone_id
       name    = "tooling.busolagbadero.click"
       type    = "A"

      alias {
       name                   = aws_lb.ext-alb.dns_name
       zone_id                = aws_lb.ext-alb.zone_id
       evaluate_target_health = true
     }
    }


    #create records for wordpress
    resource "aws_route53_record" "wordpress" {
     zone_id = data.aws_route53_zone.project_terraform_zone.zone_id
     name    = "wordpress.busolagbadero.click"
     type    = "A"

     alias {
      name                   = aws_lb.ext-alb.dns_name
      zone_id                = aws_lb.ext-alb.zone_id
      evaluate_target_health = true
     }
    }

Create the Security for all resources with the file security.tf

     #security group for alb, to allow acess from anywhere on port 80 & 443.
       resource "aws_security_group" "ext-alb-sg" {
        name        = "ext-alb-sg"
        description = "Allow TLS inbound traffic"
        vpc_id      = aws_vpc.main.id

        ingress {
         description = "HTTPS"
         from_port   = 443
         to_port     = 443
         protocol    = "tcp"
         cidr_blocks = ["0.0.0.0/0"]
        }

       ingress {
        description = "HTTP"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }

     egress {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
      }

      tags = {
       Name = "EXT-ALB-SG"
      }
    }


     #Security group for bastion to allow access into the bastion host from your IP
     resource "aws_security_group" "bastion-sg" {
       name        = "bastion-sg"
       description = "Allow incoming HTTP connections."
       vpc_id      = aws_vpc.main.id

      ingress {
       description = "SSH"
       from_port   = 22
       to_port     = 22
       protocol    = "tcp"
       cidr_blocks = ["0.0.0.0/0"]
      }

     egress {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
     }

      tags = {
       Name        = "BASTION-SG"
       Environment = var.environment
      }
     }

      #Security group for nginx reverse proxy to allow access only from the external load balancer and bastion instance 
     resource "aws_security_group" "nginx-sg" {
      name   = "nginx-sg"
      vpc_id = aws_vpc.main.id

     egress {
       from_port   = 0
       to_port     = 0
       protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
     }

      tags = {
       Name = "NGINX-SG"
      }
     }

     resource "aws_security_group_rule" "inbound-nginx-https" {
       type                     = "ingress"
       from_port                = 443
       to_port                  = 443
       protocol                 = "tcp"
       source_security_group_id = aws_security_group.ext-alb-sg.id
       security_group_id        = aws_security_group.nginx-sg.id
      }

    resource "aws_security_group_rule" "inbound-nginx-http-80" {
     type                     = "ingress"
     from_port                = 80
     to_port                  = 80
     protocol                 = "tcp"
     source_security_group_id = aws_security_group.ext-alb-sg.id
     security_group_id        = aws_security_group.nginx-sg.id
    }

    resource "aws_security_group_rule" "inbound-bastion-ssh" {
      type                     = "ingress"
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.bastion-sg.id
      security_group_id        = aws_security_group.nginx-sg.id
     }

        #Security group for internal alb, to have access only from nginx reverse proxy server
     resource "aws_security_group" "int-alb-sg" {
       name   = "int-alb-sg"
       vpc_id = aws_vpc.main.id
 
       egress {
       from_port   = 0
       to_port     = 0
       protocol    = "-1"
       cidr_blocks = ["0.0.0.0/0"]
     }

     tags = {
       Name = "INT-ALB-SG"
     }
    }

    resource "aws_security_group_rule" "inbound-ialb-https" {
     type                     = "ingress"
     from_port                = 443
     to_port                  = 443
     protocol                 = "tcp"
     source_security_group_id = aws_security_group.nginx-sg.id
     security_group_id        = aws_security_group.int-alb-sg.id
    }

     #Security group for webservers, to have access only from the internal load balancer and bastion instance
     resource "aws_security_group" "webserver-sg" {
      name   = "webserver-sg"
      vpc_id = aws_vpc.main.id

     egress {
       from_port   = 0
       to_port     = 0
       protocol    = "-1"
       cidr_blocks = ["0.0.0.0/0"]
      }

     tags = {
       Name = "WEBSERVER-SG"
     }
    }

     resource "aws_security_group_rule" "inbound-webserver-https" {
      type                     = "ingress"
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.int-alb-sg.id
      security_group_id        = aws_security_group.webserver-sg.id
     }

    resource "aws_security_group_rule" "inbound-webserver-ssh" {
     type                     = "ingress"
     from_port                = 22
     to_port                  = 22
     protocol                 = "tcp"
     source_security_group_id = aws_security_group.bastion-sg.id
     security_group_id        = aws_security_group.webserver-sg.id
    }

     #Security group for datalayer to allow traffic from webserver on nfs and mysql port ann bastion host on mysql
        resource "aws_security_group" "datalayer-sg" {
         name   = "datalayer-sg"
         vpc_id = aws_vpc.main.id

         egress {
           from_port   = 0
           to_port     = 0
           protocol    = "-1"
           cidr_blocks = ["0.0.0.0/0"]
          }

          tags = {
            Name = "DATALAYER-SG"
          }
         }

      resource "aws_security_group_rule" "inbound-nfs-port" {
       type                     = "ingress"
      from_port                = 2049
      to_port                  = 2049
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.webserver-sg.id
      security_group_id        = aws_security_group.datalayer-sg.id
     }

    resource "aws_security_group_rule" "inbound-mysql-bastion" {
      type                     = "ingress"
      from_port                = 3306
      to_port                  = 3306
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.bastion-sg.id
      security_group_id        = aws_security_group.datalayer-sg.id
     }

    resource "aws_security_group_rule" "inbound-mysql-webserver" {
      type                     = "ingress"
      from_port                = 3306
      to_port                  = 3306
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.webserver-sg.id
      security_group_id        = aws_security_group.datalayer-sg.id
     }


Create the load balancer with the file alb.tf

       # ----------------------------
       #External Load balancer for reverse proxy nginx
       #---------------------------------

        resource "aws_lb" "ext-alb" {
         name            = "ext-alb"
         internal        = false
         security_groups = [aws_security_group.ext-alb-sg.id]
         subnets         = [aws_subnet.public[0].id, aws_subnet.public[1].id]

         tags = {
          Name = "ext-alb"
         }

         ip_address_type    = "ipv4"
         load_balancer_type = "application"
        }

        #--- create a target group for the external load balancer
         resource "aws_lb_target_group" "nginx-tgt" {
          health_check {
          interval            = 10
          path                = "/healthstatus"
          protocol            = "HTTPS"
          timeout             = 5
          healthy_threshold   = 5
          unhealthy_threshold = 2
         }
         name        = "nginx-tgt"
         port        = 443
         protocol    = "HTTPS"
        target_type = "instance"
        vpc_id      = aws_vpc.main.id
       }

         #--- create a listener for the load balancer

          resource "aws_lb_listener" "nginx-listner" {
           load_balancer_arn = aws_lb.ext-alb.arn
           port              = 443
           protocol          = "HTTPS"
           certificate_arn   = aws_acm_certificate_validation.busolagbadero.certificate_arn

           default_action {
           type             = "forward"
           target_group_arn = aws_lb_target_group.nginx-tgt.arn
          }
         }

        #----------------------------
        #Internal Load Balancers for webservers
        #---------------------------------

         resource "aws_lb" "int-alb" {
           name     = "int-alb"
           internal = true

           security_groups = [aws_security_group.int-alb-sg.id]

           subnets = [aws_subnet.private[0].id, aws_subnet.private[1].id]

            tags = {
              Name = "int-alb"
            }

            ip_address_type    = "ipv4"
            load_balancer_type = "application"
           }

           # --- target group  for wordpress -------
             resource "aws_lb_target_group" "wordpress-tgt" {
               health_check {
               interval            = 10
               path                = "/healthstatus"
               protocol            = "HTTPS"
               timeout             = 5
               healthy_threshold   = 5
               unhealthy_threshold = 2
             }

              name        = "wordpress-tgt"
              port        = 443
              protocol    = "HTTPS"
              target_type = "instance"
              vpc_id      = aws_vpc.main.id
             }

         # --- target group for tooling -------
            resource "aws_lb_target_group" "tooling-tgt" {
              health_check {
              interval            = 10
              path                = "/healthstatus"
              protocol            = "HTTPS"
              timeout             = 5
              healthy_threshold   = 5
             unhealthy_threshold = 2
            }

            name        = "tooling-tgt"
            port        = 443
            protocol    = "HTTPS"
            target_type = "instance"
            vpc_id      = aws_vpc.main.id
           }

           #For this aspect a single listener was created for the wordpress which is default,
          #A rule was created to route traffic to tooling when the host header changes

            resource "aws_lb_listener" "web-listener" {
             load_balancer_arn = aws_lb.int-alb.arn
             port              = 443
             protocol          = "HTTPS"
             certificate_arn   = aws_acm_certificate_validation.busolagbadero.certificate_arn


            default_action {
            type             = "forward"
            target_group_arn = aws_lb_target_group.wordpress-tgt.arn
           }
         }

        #listener rule for tooling target

         resource "aws_lb_listener_rule" "tooling-listener" {
          listener_arn = aws_lb_listener.web-listener.arn
          priority     = 99

          action {
          type             = "forward"
          target_group_arn = aws_lb_target_group.tooling-tgt.arn
         }

         condition {
         host_header {
         values = ["tooling.busolagbadero.click"]
        }
      }
     }


Create Roles and Policies that will be attached to attached to our instance using the roles.tf file.

            resource "aws_iam_role" "ec2_instance_role" {
           name = "ec2_instance_role"
           assume_role_policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
         }
        },
      ]
    })

 
      tags = merge(
       var.tags,
        {
         Name = "aws assume role"
       },
     )
    }

    resource "aws_iam_policy" "policy" {
    name        = "ec2_instance_policy"
    description = "A test policy"
    policy = jsonencode({
     Version = "2012-10-17"
     Statement = [
       {
         Action = [
           "ec2:Describe*",
         ]
         Effect   = "Allow"
         Resource = "*"
        },
      ]

    })

    tags = merge(
     var.tags,
     {
       Name =  "aws assume policy"
      },
     )

    }

    resource "aws_iam_role_policy_attachment" "test-attach" {
        role       = aws_iam_role.ec2_instance_role.name
        policy_arn = aws_iam_policy.policy.arn
    }

        resource "aws_iam_instance_profile" "ip" {
        name = "aws_instance_profile_test"
        role =  aws_iam_role.ec2_instance_role.name
    }


Create asg-bastion-nginx.tf file, it contains resources for auto scaling group, launch templates (exist before autoscaling group).

             # creating sns topic for all the auto scaling groups
              resource "aws_sns_topic" "busola-sns" {
             name = "Default_CloudWatch_Alarms_Topic"
            }

        resource "aws_autoscaling_notification" "busola_notifications" {
          group_names = [
           aws_autoscaling_group.bastion-asg.name,
           aws_autoscaling_group.nginx-asg.name,
           aws_autoscaling_group.wordpress-asg.name,
           aws_autoscaling_group.tooling-asg.name,
          ]
          notifications = [
            "autoscaling:EC2_INSTANCE_LAUNCH",
            "autoscaling:EC2_INSTANCE_TERMINATE",
            "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
            "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
           ]

           topic_arn = aws_sns_topic.busola-sns.arn
            }

            resource "random_shuffle" "az_list" {
              input        = data.aws_availability_zones.available.names
              }
  
              resource "aws_launch_template" "bastion-launch-template" {
               image_id               = var.ami
               instance_type          = "t2.micro"
               vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  
              iam_instance_profile {
              name = aws_iam_instance_profile.ip.id
             }
  
             key_name = var.keypair
  
            placement {
            availability_zone = "random_shuffle.az_list.result"
           }
  
          lifecycle {
           create_before_destroy = true
          }
  
          tag_specifications {
            resource_type = "instance"
  
            tags = merge(
            var.tags,
          {
           Name = "bastion-launch-template"
        },
      )
      }
  
      user_data = filebase64("${path.module}/bastion.sh")
     }
  
          # ---- Autoscaling for bastion  hosts
  
           resource "aws_autoscaling_group" "bastion-asg" {
             name                      = "bastion-asg"
             max_size                  = 2
             min_size                  = 1
             health_check_grace_period = 300
             health_check_type         = "ELB"
             desired_capacity          = 1
  
            vpc_zone_identifier = [
            aws_subnet.public[0].id,
            aws_subnet.public[1].id
           ]
  
          launch_template {
            id      = aws_launch_template.bastion-launch-template.id
            version = "$Latest"
          }
          tag {
          key                 = "Name"
          value               = "bastion-launch-template"
          propagate_at_launch = true
         }
  
       }
  
        #launch template for nginx
  
        resource "aws_launch_template" "nginx-launch-template" {
         image_id               = var.ami
         instance_type          = "t2.micro"
         vpc_security_group_ids = [aws_security_group.nginx-sg.id]
  
         iam_instance_profile {
         name = aws_iam_instance_profile.ip.id
        }
  
        key_name =  var.keypair
  
        placement {
         availability_zone = "random_shuffle.az_list.result"
        }
  
        lifecycle {
          create_before_destroy = true
        }
  
        tag_specifications {
          resource_type = "instance"
  
        tags = merge(
         var.tags,
        {
          Name = "nginx-launch-template"
        },
      )
     }
  
     user_data = filebase64("${path.module}/nginx.sh")
    }
  
         # ------ Autoscslaling group for reverse proxy nginx ---------
         
  
    resource "aws_autoscaling_group" "nginx-asg" {
     name                      = "nginx-asg"
     max_size                  = 2
     min_size                  = 1
     health_check_grace_period = 300
     health_check_type         = "ELB"
     desired_capacity          = 1
  
    vpc_zone_identifier = [
      aws_subnet.public[0].id,
      aws_subnet.public[1].id
    ]
  
    launch_template {
      id      = aws_launch_template.nginx-launch-template.id
      version = "$Latest"
    }
  
    tag {
      key                 = "Name"
      value               = "nginx-launch-template"
      propagate_at_launch = true
     }
  
    }
  
           #attaching autoscaling group of nginx to external load balancer
  
    resource "aws_autoscaling_attachment" "asg_attachment_nginx" {
     autoscaling_group_name = aws_autoscaling_group.nginx-asg.id
     alb_target_group_arn   = aws_lb_target_group.nginx-tgt.arn
    }     
    
    
 Enter value below in variables.tf file
 
       variable "ami" {
        type        = string
        description = "AMI ID for the launch template"
       }

       variable "keypair" {
        type        = string
        description = "Key pair for the instances"
       }
 
       variable "account_no" {
        type        = number
        description = "the account number"
       }
       
       
   Enter value below in terraform.tfvars file
   
            ami = "ami-0b0af3577fe5e3532"

            keypair = "sikemi"

Create bastion.sh file and enter content below:

           #!/bin/bash
           yum install -y mysql
          yum install -y git tmux
          yum install -y ansible
          
Create nginx.sh file and the enter content below:
         
         #!/bin/bash
         yum install -y nginx
         systemctl start nginx
         systemctl enable nginx
         git clone https://github.com/busolagbadero/ACS-project-config.git
         mv /ACS-project-config/reverse.conf /etc/nginx/
         mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf-distro
        cd /etc/nginx/
        touch nginx.conf
        sed -n 'w nginx.conf' reverse.conf
        systemctl restart nginx
        rm -rf reverse.conf
        rm -rf /ACS-project-config
       
 Create asg-webserver-nginx.tf file for tooling and worpress, it contains resources for auto scaling group, launch templates (exist before autoscaling group).
 
           
  
              #Create asg-wordpress-tooling.tf and paste the following code
  
              #launch template for wordpress
  
               resource "aws_launch_template" "wordpress-launch-template" {
                image_id               = var.ami
                instance_type          = "t2.micro"
                vpc_security_group_ids = [aws_security_group.webserver-sg.id]
  
                iam_instance_profile {
                   name = aws_iam_instance_profile.ip.id
                 }
  
                 key_name = var.keypair
  
                 placement {
                   availability_zone = "random_shuffle.az_list.result"
                 }
  
                 lifecycle {
                    create_before_destroy = true
                 }
  
                 tag_specifications {
                   resource_type = "instance"
  
      tags = merge(
      var.tags,
        {
           Name = "wordpress-launch-template"
        },
      )
  
     }
  
     user_data = filebase64("${path.module}/wordpress.sh")
    }
  
              # ---- Autoscaling for wordpress application
  
          resource "aws_autoscaling_group" "wordpress-asg" {
           name                      = "wordpress-asg"
           max_size                  = 2
           min_size                  = 1
           health_check_grace_period = 300
           health_check_type         = "ELB"
           desired_capacity          = 1
           vpc_zone_identifier = [
  
              aws_subnet.private[0].id,
              aws_subnet.private[1].id
           ]
  
           launch_template {
            id      = aws_launch_template.wordpress-launch-template.id
            version = "$Latest"
           }
           tag {
              key                 = "Name"
              value               = "wordpress-asg"
              propagate_at_launch = true
             }
            }
  
                #attaching autoscaling group of  wordpress application to internal loadbalancer
         resource "aws_autoscaling_attachment" "asg_attachment_wordpress" {
           autoscaling_group_name = aws_autoscaling_group.wordpress-asg.id
           alb_target_group_arn   = aws_lb_target_group.wordpress-tgt.arn
          }
  
              #launch template for toooling
                resource "aws_launch_template" "tooling-launch-template" {
                  image_id               = var.ami
                  instance_type          = "t2.micro"
                  vpc_security_group_ids = [aws_security_group.webserver-sg.id]
  
                  iam_instance_profile {
                  name = aws_iam_instance_profile.ip.id
                 }
  
                key_name = var.keypair
  
                placement {
                 availability_zone = "random_shuffle.az_list.result"
                }
  
                lifecycle {
                 create_before_destroy = true
                }
  
                tag_specifications {
                  resource_type = "instance"
  
            tags = merge(
             var.tags,
              {
                 Name = "tooling-launch-template"
              },
            )
  
          }
  
        user_data = filebase64("${path.module}/tooling.sh")
       }
  
            #---- Autoscaling for tooling -----
  
         resource "aws_autoscaling_group" "tooling-asg" {
          name                      = "tooling-asg"
          max_size                  = 2
          min_size                  = 1
          health_check_grace_period = 300
          health_check_type         = "ELB"
          desired_capacity          = 1
  
       vpc_zone_identifier = [
   
        aws_subnet.private[0].id,
        aws_subnet.private[1].id
      ]
  
    launch_template {
      id      = aws_launch_template.tooling-launch-template.id
      version = "$Latest"
    }
  
    tag {
      key                 = "Name"
      value               = "tooling-launch-template"
      propagate_at_launch = true
     }
    }
                     
                     #attaching autoscaling group of  tooling application to internal loadbalancer
                  
                  resource "aws_autoscaling_attachment" "asg_attachment_tooling" {
                     autoscaling_group_name = aws_autoscaling_group.tooling-asg.id
                     alb_target_group_arn   = aws_lb_target_group.tooling-tgt.arn
                    } 


Creates output.tf, its a way of printing out value

                  output "alb_dns_name" {
                  value       = aws_lb.ext-alb.dns_name
                  description = "External load balance arn"
                 }

Create efs.tf file contains resources to create kms key used for the elastic file system and RDS used for encryption purposes.

                # create key from key management system

               resource "aws_kms_key" "ACS-kms" {
                description = "KMS key "
                policy      = <<EOF
               {
               "Version": "2012-10-17",
               "Id": "kms-key-policy",
               "Statement": [
                 {
                   "Sid": "Enable IAM User Permissions",
                   "Effect": "Allow",
                   "Principal": { "AWS": "arn:aws:iam::${var.account_no}:user/admin" },
                   "Action": "kms:*",
                   "Resource": "*"
                   }
                 ]
                }
                EOF
                }

        #create key alias
                      
          resource "aws_kms_alias" "alias" {
           name          = "alias/kms"
           target_key_id = aws_kms_key.ACS-kms.key_id
          }

       #create Elastic file system
                      
        resource "aws_efs_file_system" "ACS-efs" {
          encrypted  = true
          kms_key_id = aws_kms_key.ACS-kms.arn

          tags = {
            Name = "ACS-efs"
          }
        }


         #set first mount target for the EFS 
                      
          resource "aws_efs_mount_target" "subnet-1" {
            file_system_id  = aws_efs_file_system.ACS-efs.id
            subnet_id       = aws_subnet.private[0].id
            security_groups = [aws_security_group.datalayer-sg.id]
          }


         #set second mount target for the EFS 
                      
        resource "aws_efs_mount_target" "subnet-2" {
         file_system_id  = aws_efs_file_system.ACS-efs.id
         subnet_id       = aws_subnet.private[1].id
         security_groups = [aws_security_group.datalayer-sg.id]
        }


       #create access point for wordpress
                      
       resource "aws_efs_access_point" "wordpress" {
        file_system_id = aws_efs_file_system.ACS-efs.id

        posix_user {
        gid = 0
        uid = 0
       }

      root_directory {
       path = "/wordpress"

       creation_info {
         owner_gid   = 0
         owner_uid   = 0
         permissions = 0755
        }

      }

    }


         #create access point for tooling
                      
       resource "aws_efs_access_point" "tooling" {
        file_system_id = aws_efs_file_system.ACS-efs.id
        posix_user {
         gid = 0
         uid = 0
       }

       root_directory {

        path = "/tooling"

        creation_info {
         owner_gid   = 0
         owner_uid   = 0
        permissions = 0755
       }

      }
     }      
  
  
 Enter value below into variables.tf
 
          variable "account_no" {
            type        = number
            description = "the account number"
           }
 In the terraform.tfvar, enter the value below
 
          account_no = "732945705237"
          
 Create RDS using rds.tf for database.
 
           # This section will create the subnet group for the RDS  instance using the private subnet
           
                resource "aws_db_subnet_group" "ACS-rds" {
                  name       = "acs-rds"
                  subnet_ids = [aws_subnet.private[2].id, aws_subnet.private[3].id]

                  tags = merge(
                   var.tags,
                   {
                     Name = "ACS-rds"
                  },
               )
            }


        #create the RDS instance with the subnets group
           resource "aws_db_instance" "ACS-rds" {
            allocated_storage      = 20
            storage_type           = "gp2"
            engine                 = "mysql"
            engine_version         = "5.7"
            instance_class         = "db.t2.micro"
            name                   = "busoladb"
            username               = var.master-username
            password               = var.master-password
            parameter_group_name   = "default.mysql5.7"
            db_subnet_group_name   = aws_db_subnet_group.ACS-rds.name
            skip_final_snapshot    = true
            vpc_security_group_ids = [aws_security_group.datalayer-sg.id]
            multi_az               = "true"
          }


Enter values below in variable.tf file

              variable "master-username" {
                 type        = string
                 description = "RDS admin username"
               }

              variable "master-password" {
                type        = string
                description = "RDS master password"
               }
               
  Enter values below in terraform.tfvars file
  
            master-username = "busola"

            master-password = "admin12345"
            
 Run terraform plan to check error and run terraform apply to install all necessary resources.
 
 
 
![sunday37](https://user-images.githubusercontent.com/94229949/231914291-c3bd784c-855d-4201-ba86-7c7da9114868.png)


![sunday38](https://user-images.githubusercontent.com/94229949/231914335-7ed7e9ac-8275-4a4f-a68a-96640028c800.png)


![sunday39](https://user-images.githubusercontent.com/94229949/231914350-221d0ef7-f04e-4d6a-92d6-c3f3715526d4.png)


![sunday40](https://user-images.githubusercontent.com/94229949/231914573-1aa904e4-a646-4cfe-8409-28ddcb927d56.png)


![sunday41](https://user-images.githubusercontent.com/94229949/231914584-a848a24e-ec55-4d3a-9864-9627e9dcbbde.png)


![sunday42](https://user-images.githubusercontent.com/94229949/231914600-e4607238-5564-4b2f-95b4-bcf4f24862bf.png)

![sunday49](https://user-images.githubusercontent.com/94229949/231914635-93ccde7f-db6c-403f-ab0a-99421d0beae5.png)

![sunday48](https://user-images.githubusercontent.com/94229949/231914662-7c977a19-b035-464d-abef-754434dbb001.png)

![sunday47](https://user-images.githubusercontent.com/94229949/231914692-a9d9ef3c-acc5-4c46-b80d-84a2880d457f.png)



![sunday46](https://user-images.githubusercontent.com/94229949/231914709-b990c624-0d81-4fc5-aad9-abbdbc1fdaec.png)


![sunday45](https://user-images.githubusercontent.com/94229949/231914726-5243735a-5f80-4738-bbbb-903498729994.png)


![sunday44](https://user-images.githubusercontent.com/94229949/231914737-4486f9c4-001d-4866-a1d7-7efa722be229.png)


![sunday58](https://user-images.githubusercontent.com/94229949/231914806-4becc065-2b4b-4cc2-b43d-794dec784dbd.png)


![sunday57](https://user-images.githubusercontent.com/94229949/231914830-f8b3ed43-9c3b-4a19-899f-a1d7587701c0.png)

![sunday56](https://user-images.githubusercontent.com/94229949/231914878-0132c2e6-8054-4875-a47d-8d1b4d9e3363.png)


