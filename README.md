# AWS Security Data Lake

Last Update: May 2020

## Overview

The AWS security data lake solution imports AWS native logs from CloudWatch into Elasticsearch including

* CloudTrail
* GuardDuty alarms

## Features

* CloudTrail logs are enrichted with GeoIP data
* CloudTrail logs are marked as "knownGood" if fields match corresponding regex statements defined in a configuration file hosted on S3


## Legacy Solution Approach

Lambda's using Logstash require a Logstash instance running on EC2. This approach was abandoned as it requires a EC2 instance or container. 
The new solution approach performs GeoIP lookup and other log format transformations directly inside the Lambda functions and sends logs to Kinesis which writes them to Elasticsearch.


