provider "aws" {
  region = "us-east-1" # AWS Organizations is a global service, but a region is required.
}

data "aws_caller_identity" "current" {}

resource "aws_organizations_policy" "SCP1" {
  name        = "EnforcePermissionsBoundaryOnRoleCreation"
  description = "Denies creating IAM roles without the required permissions boundary."

  content = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "RequirePermissionsBoundaryOnRoleCreation",
        "Effect" : "Deny",
        "Action" : [
          "iam:CreateRole"
        ],
        "Resource" : "*",
        "Condition" : {
          # This condition checks if the ARN of the permissions boundary attached
          # during role creation is NOT the one you have approved.
          # The user creating the role MUST specify the exact permissions boundary below.
          "StringNotEquals" : {
            "iam:PermissionsBoundary" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/YourDeveloperBoundaryPolicy"
          }
        }
      },
       {
        "Sid" : "DenyNonSSLParameterGroupForDBInstance",
        "Effect" : "Deny",
        "Action" : [
          "rds:CreateDBInstance",
          "rds:ModifyDBInstance"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringNotEquals" : {
            "rds:DBParameterGroupName" : [
              "custom-mysql8-enforce-ssl",
              "custom-postgres15-enforce-ssl",
              "default.mysql8.0"
            ]
          }
        }
      },
      {
        "Sid" : "DenyNonSSLParameterGroupForDBCluster",
        "Effect" : "Deny",
        "Action" : [
          "rds:CreateDBCluster",
          "rds:ModifyDBCluster"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringNotEquals" : {
            "rds:DBClusterParameterGroupName" : [
              "custom-aurora-mysql8-enforce-ssl",
              "custom-aurora-postgres15-enforce-ssl",
              "default.aurora-mysql8.0"
            ]
          }
        }
      }
    ]
  })
}


resource "aws_organizations_policy_attachment" "boundary_policy_attachment" {
  policy_id = aws_organizations_policy.SCP1.id
  target_id = "INSERT ROOT ID" # <-- REPLACE WITH YOUR Root
}

# For the purposes of this work sample, I didnt want to leave the OU or root ID so you would need to swap it out. 



