# AWS Security Data Lake

Last Update: May 2020

## Overview

The AWS security data lake solution imports AWS native logs from CloudWatch into Elasticsearch including

* CloudTrail
* GuardDuty alarms

## Features

* CloudTrail logs are enrichted with GeoIP data
* CloudTrail logs are marked as "knownGood" if fields match corresponding regex statements defined in a configuration file hosted on S3





