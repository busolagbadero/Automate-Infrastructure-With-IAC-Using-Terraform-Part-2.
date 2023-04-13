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
