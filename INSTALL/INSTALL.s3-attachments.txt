Using S3 as an attachment store
===============================

It is possible to use Amazon's Simple Storage Service (S3) to store event attachments
to allow for a stateless MISP setup (i.e for containerisation)

There's a massive caveat here so let me make this incredibly clear

##############################################
#        WARNING WARNING WARNING             #
#                                            #
#    Storing malware is against amazon's     #
#            terms of service.               #
#                                            #
#    DO NOT USE THIS UNLESS YOU HAVE         # 
#      THEIR EXPLICIT PERMISSION             #
##############################################      

0. Installing Dependencies
--------------------------

Install the AWS PHP SDK

```bash
cd /var/www/MISP/app
sudo -u www-data php composer.phar config vendor-dir Vendor
sudo -u www-data php composer.phar require aws/aws-sdk-php
```

1. Creating an S3 bucket
-------------------------

Go to https://s3.console.aws.amazon.com/s3/home

And create a bucket. It has to have a globally unique name, and
this cannot be changed later on.

2a. Using an EC2 instance for MISP
-----------------------------------

If you run MISP on EC2, this will be super duper easy peasy.

Simply create an IAM role with the following permissions and assign it to the instance
by right-clicking and selecting "Instance Settings -> Attach/Replace IAM role"

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
        "Sid": "PermitMISPAttachmentsToS3",
        "Effect": "Allow",
        "Action": [
            "s3:*"
        ],
        "Resource": [
            "arn:aws:s3:::your-bucket-name"
        ]
    }
  ]
}
```

2b. Using AWS access keys
-------------------------

This is not recommended, but it works I think.

Create a new programmatic access user via IAM and apply the same
policy outlined above.

Copy the access keys and save them for the next step

3. Setting up MISP
------------------

In Administration -> Server Settings & Maintenance -> MISP settings

    Set MISP.attachments_dir to "s3://"

In Administration -> Server Settings & Maintenance -> Plugin Settings -> S3

    Set S3_enable to True
    Set S3_bucket-name to the bucket you created earlier
    Set S3_region to your region
    
    ONLY IF YOU DID NOT USE THE EC2 METHOD
        Set aws_access_key and aws_secret_key to the ones you created in 2b

Now theoretically it should work.

Addendum
========

If you are migrating a server currently in use, simply copy the directory structure from
the attachments folder (usually /var/www/MISP/app/files) to S3 and everything should 
continue to work.
