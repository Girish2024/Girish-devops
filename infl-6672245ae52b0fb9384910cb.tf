resource "aws_iam_role" "TerraformExecutionRole-97d" {
  assume_role_policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
})
  description        = "Allows EC2 instances to call AWS services on your behalf."
  inline_policy {
    name   = "vpc-pm"
    policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkAcl",
        "ec2:CreateTags",
        "ec2:DeleteNetworkAcl",
        "ec2:DeleteNetworkAclEntry",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute",
        "iam:PassRole"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "ec2:Describe*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry"
      ],
      "Resource": "*"
    }
  ]
})
  }
  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/AmazonSNSFullAccess", "arn:aws:iam::aws:policy/CloudWatchEventsFullAccess"]
  name                = "TerraformExecutionRole"
}


resource "aws_iam_user" "sanjana-810" {
  name = "sanjana"
  tags = {
    "REDACTED-BY-FIREFLY:3d018066ff2621704f6b977284c50a5049535dca59489e10158eedbe3c596ea3:sha256" = "cli"
    "REDACTED-BY-FIREFLY:9933a6c4221ede34462640cd0e5a2e01e90795726ba3ad1200d0a08af3a658db:sha256" = "for test"
  }
}


resource "aws_iam_user" "girish-3ba" {
  name = "girish"
}


resource "aws_iam_instance_profile" "TerraformExecutionRole-661" {
  name = "TerraformExecutionRole"
  role = "TerraformExecutionRole"
}


resource "aws_security_group" "launch-wizard-2-62a" {
  description = "launch-wizard-2 created 2024-05-27T05:44:25.267Z"
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
  }
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    protocol    = "tcp"
    to_port     = 22
  }
  name   = "launch-wizard-2"
  vpc_id = "vpc-0783d966a61c50485"
  # The following attributes have default values introduced when importing the resource into terraform: [revoke_rules_on_delete timeouts]
  lifecycle {
    ignore_changes = [revoke_rules_on_delete, timeouts]
  }
}


resource "aws_eks_addon" "_76c768fd-ce1b-b88c-3625-7d4b2d60067b-c60" {
  addon_name    = "kube-proxy"
  addon_version = "v1.29.0-eksbuild.1"
  cluster_name  = "test-cluster"
}


resource "aws_eks_addon" "_0ac768fd-ce1c-0085-3cda-29fee8c7795b-9ad" {
  addon_name    = "vpc-cni"
  addon_version = "v1.16.0-eksbuild.1"
  cluster_name  = "test-cluster"
}


resource "aws_eks_addon" "d0c768fd-ce14-0f3a-adc9-4c62da9e18c7-3c4" {
  addon_name    = "coredns"
  addon_version = "v1.11.1-eksbuild.4"
  cluster_name  = "test-cluster"
}


resource "aws_eks_addon" "fac768fd-ce22-26e4-bc51-378c5d3acc9b-f23" {
  addon_name    = "eks-pod-identity-agent"
  addon_version = "v1.2.0-eksbuild.1"
  cluster_name  = "test-cluster"
}


resource "aws_cloudwatch_event_target" "Id44d1e024-ecd4-423e-be1e-5b2e41c61cbe-601" {
  arn       = "arn:aws:sns:us-east-1:471112682367:AWSHealthNotifications"
  rule      = "AWSHealthNotifications-Rule"
  target_id = "Id44d1e024-ecd4-423e-be1e-5b2e41c61cbe"
}


resource "aws_kms_key" "e8168653-d7fd-4f54-b3f0-93e8c1024f06-32f" {
  description = "Encryption Key for EBS Volumes"
  policy      = jsonencode({
  "Id": "key-consolepolicy-3",
  "Statement": [
    {
      "Action": "kms:*",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::471112682367:root"
      },
      "Resource": "*",
      "Sid": "Enable IAM User Permissions"
    },
    {
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:RotateKeyOnDemand"
      ],
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::471112682367:user/sanjana",
          "arn:aws:iam::471112682367:user/girish"
        ]
      },
      "Resource": "*",
      "Sid": "Allow access for Key Administrators"
    },
    {
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::471112682367:user/sanjana",
          "arn:aws:iam::471112682367:user/girish"
        ]
      },
      "Resource": "*",
      "Sid": "Allow use of the key"
    },
    {
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Condition": {
        "Bool": {
          "kms:GrantIsForAWSResource": "true"
        }
      },
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::471112682367:user/sanjana",
          "arn:aws:iam::471112682367:user/girish"
        ]
      },
      "Resource": "*",
      "Sid": "Allow attachment of persistent resources"
    }
  ],
  "Version": "2012-10-17"
})
}


resource "aws_kms_key" "_09c04a2a-cde5-4211-a3a2-d22cff536b8d-097" {
  policy = jsonencode({
  "Id": "key-consolepolicy-3",
  "Statement": [
    {
      "Action": "kms:*",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::471112682367:root"
      },
      "Resource": "*",
      "Sid": "Enable IAM User Permissions"
    },
    {
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::471112682367:user/girish"
      },
      "Resource": "*",
      "Sid": "Allow use of the key"
    },
    {
      "Action": [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ],
      "Condition": {
        "Bool": {
          "kms:GrantIsForAWSResource": "true"
        }
      },
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::471112682367:user/girish"
      },
      "Resource": "*",
      "Sid": "Allow attachment of persistent resources"
    }
  ],
  "Version": "2012-10-17"
})
}


resource "aws_instance" "test-aws-notification-be7" {
  ami                         = "ami-08a0d1e16fc3f61ea"
  associate_public_ip_address = true
  availability_zone           = "us-east-1b"
  cpu_core_count              = 1
  cpu_threads_per_core        = 1
  credit_specification {
    cpu_credits = "standard"
  }
  disable_api_termination = false
  ebs_optimized           = false
  enclave_options {
    enabled = false
  }
  hibernation                          = false
  iam_instance_profile                 = "TerraformExecutionRole"
  instance_initiated_shutdown_behavior = "stop"
  instance_type                        = "t2.micro"
  metadata_options {
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }
  monitoring = false
  private_ip = "172.31.43.192"
  root_block_device {
    iops        = 3000
    throughput  = 125
    volume_size = 8
    volume_type = "gp3"
  }
  security_groups = ["launch-wizard"]
  subnet_id       = "subnet-0061f9e97d7c0b454"
  tags = {
    Name = "test-aws-notification"
  }
  tenancy                = "default"
  vpc_security_group_ids = ["sg-02e3c9ea81c1355fe"]
  # The following attributes have default values introduced when importing the resource into terraform: [timeouts]
  lifecycle {
    ignore_changes = [timeouts]
  }
}


resource "aws_s3_bucket_acl" "adasdasd33refdsfdsfd-7f8" {
  access_control_policy {
    grant {
      grantee {
        id   = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    owner {
      display_name = "sanjanamahajan2001"
      id           = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
    }
  }
  bucket = "adasdasd33refdsfdsfd"
}


resource "aws_key_pair" "sj-b18" {
  key_name   = "sj"
  public_key = "PUT-VALUE-HERE"
  # The following attributes are sensitive values redacted by Firefly and should be replaced with your own: [public_key]
  lifecycle {
    ignore_changes = [public_key]
  }
}


resource "aws_ebs_volume" "vol-01c73e9b721f81d9e-a53" {
  availability_zone    = "ap-south-1b"
  encrypted            = false
  iops                 = 3000
  multi_attach_enabled = false
  size                 = 8
  snapshot_id          = "snap-0910702638699cf8b"
  throughput           = 125
  type                 = "gp3"
}


resource "aws_ebs_volume" "vol-03a2db150531dab28-c45" {
  availability_zone    = "ap-south-1a"
  encrypted            = true
  iops                 = 3000
  kms_key_id           = "arn:aws:kms:ap-south-1:471112682367:key/e8168653-d7fd-4f54-b3f0-93e8c1024f06"
  multi_attach_enabled = false
  size                 = 8
  snapshot_id          = "snap-0df99f12c2c63a894"
  throughput           = 125
  type                 = "gp3"
}


resource "aws_s3_bucket_server_side_encryption_configuration" "myawsbucket1234566-d22" {
  bucket = "myawsbucket1234566"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}


resource "aws_s3_bucket_versioning" "testing-mfa-delete-075" {
  bucket = "testing-mfa-delete"
  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_s3_bucket_versioning" "myawsbucket1234566-358" {
  bucket = "myawsbucket1234566"
  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_s3_bucket_acl" "myawsbucket1234566-74b" {
  access_control_policy {
    grant {
      grantee {
        id   = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    owner {
      id = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
    }
  }
  bucket = "myawsbucket1234566"
}


resource "aws_s3_bucket_public_access_block" "myawsbucket1234566-e95" {
  block_public_acls       = true
  block_public_policy     = true
  bucket                  = "myawsbucket1234566"
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_public_access_block" "aws-cloudtrail-logs-471112682367-75c601e4-dea" {
  block_public_acls       = true
  block_public_policy     = true
  bucket                  = "aws-cloudtrail-logs-471112682367-75c601e4"
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_public_access_block" "adasdasd33refdsfdsfd-684" {
  block_public_acls       = true
  block_public_policy     = true
  bucket                  = "adasdasd33refdsfdsfd"
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_iam_role" "eks-cluster-role-534" {
  assume_role_policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
})
  description        = "Allows access to other AWS service resources that are required to operate clusters managed by EKS."
  inline_policy {
    name   = "AmazonEKSClusterCloudWatchMetricsPolicy"
    policy = jsonencode({
  "Statement": [
    {
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ],
  "Version": "2012-10-17"
})
  }
  inline_policy {
    name   = "AmazonEKSClusterNLBPolicy"
    policy = jsonencode({
  "Statement": [
    {
      "Action": [
        "elasticloadbalancing:*",
        "ec2:CreateSecurityGroup",
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ],
  "Version": "2012-10-17"
})
  }
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy", "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"]
  name                = "eks-cluster-role"
}


resource "aws_cloudfront_cache_policy" "UseOriginCacheControlHeaders-eb2" {
  comment     = "Policy for origins that return Cache-Control headers. Query strings are not included in the cache key."
  default_ttl = 0
  name        = "UseOriginCacheControlHeaders"
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "all"
    }
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["host", "origin", "x-http-method", "x-http-method-override", "x-method-override"]
      }
    }
    query_strings_config {
      query_string_behavior = "none"
    }
  }
}


resource "aws_cloudfront_cache_policy" "UseOriginCacheControlHeaders-QueryStrings-ab1" {
  comment     = "Policy for origins that return Cache-Control headers and serve different content based on values present in the query string."
  default_ttl = 0
  name        = "UseOriginCacheControlHeaders-QueryStrings"
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "all"
    }
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["host", "origin", "x-http-method", "x-http-method-override", "x-method-override"]
      }
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}


resource "aws_cloudtrail" "asdfghjk-26e" {
  cloud_watch_logs_group_arn = "arn:aws:logs:ap-south-1:471112682367:log-group:aws-cloudtrail-logs-471112682367-01f73141:*"
  cloud_watch_logs_role_arn  = "arn:aws:iam::471112682367:role/service-role/post-processing-etl-test-trail"
  enable_log_file_validation = true
  enable_logging             = true
  event_selector {
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::myawsbucket1234566/"]
    }
    include_management_events = false
    read_write_type           = "All"
  }
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = false
  name                          = "asdfghjk"
  s3_bucket_name                = "aws-cloudtrail-logs-471112682367-75c601e4"
}


resource "aws_security_group" "launch-wizard-1-b34" {
  description = "launch-wizard-1 created 2024-04-18T12:28:47.354Z"
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
  }
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    protocol    = "tcp"
    to_port     = 22
  }
  name   = "launch-wizard-1"
  vpc_id = "vpc-0783d966a61c50485"
  # The following attributes have default values introduced when importing the resource into terraform: [revoke_rules_on_delete timeouts]
  lifecycle {
    ignore_changes = [revoke_rules_on_delete, timeouts]
  }
}


resource "aws_network_acl" "default-vpc-acl-4c6" {
  egress {
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    protocol   = "-1"
    rule_no    = 100
    to_port    = 0
  }
  ingress {
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    protocol   = "-1"
    rule_no    = 100
    to_port    = 0
  }
  tags = {
    Name = "default-vpc-acl"
  }
  vpc_id = "vpc-0de58b3f9a4dfa0d7"
}


resource "aws_cloudwatch_log_group" "aws-cloudtrail-logs-471112682367-01f73141-cb6" {
  name = "aws-cloudtrail-logs-471112682367-01f73141"
}


resource "aws_kms_alias" "aliasVolume-Encryption-Key-5c3" {
  name          = "alias/Volume-Encryption-Key"
  target_key_id = "e8168653-d7fd-4f54-b3f0-93e8c1024f06"
}


resource "aws_kms_alias" "aliasaasf-0e8" {
  name          = "alias/aasf"
  target_key_id = "09c04a2a-cde5-4211-a3a2-d22cff536b8d"
}


resource "aws_security_group" "launch-wizard-997" {
  description = "launch-wizard created 2024-06-17T13:30:21.296Z"
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
  }
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    protocol    = "tcp"
    to_port     = 22
  }
  name   = "launch-wizard"
  vpc_id = "vpc-0de58b3f9a4dfa0d7"
  # The following attributes have default values introduced when importing the resource into terraform: [revoke_rules_on_delete timeouts]
  lifecycle {
    ignore_changes = [revoke_rules_on_delete, timeouts]
  }
}


resource "aws_s3_bucket" "myawsbucket1234566-3b6" {
  bucket = "myawsbucket1234566"
}


resource "aws_s3_bucket" "testing-mfa-delete-847" {
  bucket = "testing-mfa-delete"
}


resource "aws_internet_gateway" "igw-0ba1b035c986c98a8-d67" {
  vpc_id = "vpc-005e851f91b903276"
}


resource "aws_iam_policy" "mfa-permissions-for-s3-ca0" {
  name   = "mfa-permissions-for-s3"
  policy = jsonencode({
  "Statement": [
    {
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      },
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::example-bucket-name/*"
    },
    {
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::example-bucket-name",
        "arn:aws:s3:::example-bucket-name/*"
      ]
    }
  ],
  "Version": "2012-10-17"
})
}


resource "aws_eks_cluster" "test-cluster-bfe" {
  kubernetes_network_config {
    service_ipv4_cidr = "10.100.0.0/16"
  }
  name     = "test-cluster"
  role_arn = "arn:aws:iam::471112682367:role/eks-cluster-role"
  version  = "1.29"
  vpc_config {
    endpoint_private_access = true
    public_access_cidrs     = ["0.0.0.0/0"]
    security_group_ids      = ["sg-0c1afeeb3f93aa903"]
    subnet_ids              = ["subnet-0373324cf7f31f015", "subnet-060042edcddfb1ee6", "subnet-0f297065fdb960f3f"]
  }
}


resource "aws_sns_topic" "AWSHealthNotifications-202" {
  display_name = "AWSHealthNotifications"
  name         = "AWSHealthNotifications"
  policy       = jsonencode({
  "Version": "2008-10-17",
  "Id": "__default_policy_ID",
  "Statement": [
    {
      "Sid": "__default_statement_ID",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "SNS:Publish",
        "SNS:RemovePermission",
        "SNS:SetTopicAttributes",
        "SNS:DeleteTopic",
        "SNS:ListSubscriptionsByTopic",
        "SNS:GetTopicAttributes",
        "SNS:AddPermission",
        "SNS:Subscribe"
      ],
      "Resource": "arn:aws:sns:us-east-1:471112682367:AWSHealthNotifications",
      "Condition": {
        "StringEquals": {
          "AWS:SourceOwner": "471112682367"
        }
      }
    },
    {
      "Sid": "AWSEvents_AWSHealthNotifications-Rule_Id44d1e024-ecd4-423e-be1e-5b2e41c61cbe",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:471112682367:AWSHealthNotifications"
    }
  ]
})
}


resource "aws_instance" "voume_test-349" {
  ami                         = "ami-0cc9838aa7ab1dce7"
  associate_public_ip_address = true
  availability_zone           = "ap-south-1a"
  cpu_core_count              = 1
  cpu_threads_per_core        = 1
  credit_specification {
    cpu_credits = "standard"
  }
  disable_api_termination = false
  ebs_optimized           = false
  enclave_options {
    enabled = false
  }
  hibernation                          = false
  instance_initiated_shutdown_behavior = "stop"
  instance_type                        = "t2.micro"
  key_name                             = "sj"
  metadata_options {
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }
  monitoring = false
  private_ip = "172.31.45.206"
  root_block_device {
    delete_on_termination = false
    encrypted             = true
    iops                  = 3000
    kms_key_id            = "arn:aws:kms:ap-south-1:471112682367:key/e8168653-d7fd-4f54-b3f0-93e8c1024f06"
    throughput            = 125
    volume_size           = 8
    volume_type           = "gp3"
  }
  security_groups = ["launch-wizard-2"]
  subnet_id       = "subnet-0236085011772ba45"
  tags = {
    Name = "voume_test"
  }
  tenancy                = "default"
  vpc_security_group_ids = ["sg-0c0723d0af4db7186"]
  # The following attributes have default values introduced when importing the resource into terraform: [timeouts]
  lifecycle {
    ignore_changes = [timeouts]
  }
}


resource "aws_instance" "TF-cf3" {
  ami                         = "ami-001843b876406202a"
  associate_public_ip_address = false
  availability_zone           = "ap-south-1b"
  cpu_core_count              = 1
  cpu_threads_per_core        = 1
  credit_specification {
    cpu_credits = "standard"
  }
  disable_api_termination = false
  ebs_optimized           = false
  enclave_options {
    enabled = false
  }
  hibernation                          = false
  instance_initiated_shutdown_behavior = "stop"
  instance_type                        = "t2.micro"
  key_name                             = "sj"
  metadata_options {
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
  }
  monitoring      = false
  private_ip      = "172.31.6.29"
  security_groups = ["launch-wizard-1"]
  subnet_id       = "subnet-09fe36e1bc01100cd"
  tags = {
    Name = "TF"
  }
  tenancy                = "default"
  vpc_security_group_ids = ["sg-03c2c67c080b6db1d"]
  # The following attributes have default values introduced when importing the resource into terraform: [timeouts]
  lifecycle {
    ignore_changes = [timeouts]
  }
}


resource "aws_ebs_volume" "vol-0aea85db971c04b55-03d" {
  availability_zone    = "ap-south-1a"
  encrypted            = true
  iops                 = 3000
  kms_key_id           = "arn:aws:kms:ap-south-1:471112682367:key/e8168653-d7fd-4f54-b3f0-93e8c1024f06"
  multi_attach_enabled = false
  size                 = 8
  snapshot_id          = "snap-05a216c29fce9cf52"
  throughput           = 125
  type                 = "gp3"
}


resource "aws_ebs_volume" "vol-02e5879cb7b644a09-b5f" {
  availability_zone    = "ap-south-1a"
  encrypted            = false
  iops                 = 3000
  multi_attach_enabled = false
  size                 = 8
  snapshot_id          = "snap-0367a3fe302b78a89"
  throughput           = 125
  type                 = "gp3"
}


resource "aws_s3_bucket_server_side_encryption_configuration" "aws-cloudtrail-logs-471112682367-75c601e4-06b" {
  bucket = "aws-cloudtrail-logs-471112682367-75c601e4"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}


resource "aws_s3_bucket_server_side_encryption_configuration" "testing-mfa-delete-a06" {
  bucket = "testing-mfa-delete"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}


resource "aws_s3_bucket_acl" "testing-mfa-delete-2e5" {
  access_control_policy {
    grant {
      grantee {
        id   = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    owner {
      id = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
    }
  }
  bucket = "testing-mfa-delete"
}


resource "aws_s3_bucket_acl" "aws-cloudtrail-logs-471112682367-75c601e4-cfe" {
  access_control_policy {
    grant {
      grantee {
        id   = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    owner {
      id = "f10a75c9d5a77a0f2d9b01b954d4d3bcc878bf6b189184265ffddd68d9e06f90"
    }
  }
  bucket = "aws-cloudtrail-logs-471112682367-75c601e4"
}


resource "aws_s3_bucket_public_access_block" "testing-mfa-delete-fb7" {
  block_public_acls       = true
  block_public_policy     = true
  bucket                  = "testing-mfa-delete"
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket" "adasdasd33refdsfdsfd-756" {
  bucket = "adasdasd33refdsfdsfd"
}

