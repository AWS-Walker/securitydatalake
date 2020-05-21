# Prerequisites

* Setup: CloudTrail > CloudWatch Subscription > Kinesis Streams > Lambda Trigger > Elasticsearch
* add geolite.py into root directory of Lambda function
* Layers: add layer "Layer ES" and "Layer GeoIP"
* Timeout: min 2min (if not working in bulk)
* Memory: typically used 90MB
* Permissions: Role (get kinesis records, write to ES)
* Upload S3 config file into S3 bucket and update bucket and file name to the config of this Lambda

# TO DO

* Find the right trigger batch size 
* single ES put or bulk?
* KMS