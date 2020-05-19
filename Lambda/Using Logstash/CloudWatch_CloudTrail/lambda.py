#
# CloudWatch > Log groups > subscription > lambda
#
# Example Event:
#{"awslogs": {"data": "H4sIAAAAAAAAAO1U2W7jNhT9lUDPoUeiJIrSm2AnrjpJZxAbHWDiIKDEa0WotpLUuG6Qf+8VZceDzIKuQB/yZJl3O+fc5dFpQGtRwnrfg5M4i3Sd3l9frFbp8sI5d7pdCwqfOfM45SxmPKb4XHflUnVDj5Z53Q1yrURVU/v5QZjiYXJZGQWieRF9fwq4HzQBoQ0ZU+oh14WqelN17WVVG1DaSW6dK9HkUkyZ7teAzotK97XYX3yC1mjnzlY6/EluH51KYkE/DAIvDj0/8imPAi+KOMXqPmMBZ67r0yCgcRyhLWZeEPtR6LOYegxxmAoFMaJBbl6IeCPqstCl7PwoFKZ/3DgwVvwZQSLcjZNsHG/mhhvnfOMMGlQm0VqZPVrQ16C01ifVemhA3nQ1WNdeVW1R9aLO5GS/eZcGN29/YD9es6sF8z/Mo6s0ETv9qat/0STT0JZCSRsr1FQXf0ePRBudJJ8LnYipGlFY7s2yk2++kagouqE1BwifZziakfdb2B8xrrJnjPPFcpm9yyLrqNENxZh3rYHfzMT88JYhElAvxPhrKnyVcyWaF5yPXP8Ms7FRP4lmQmNjnvB1B3kmL0GCEuMoLoQRI/DRJIxRVT4Y0BOVZivSwTyMrS6EganMVtR64lXgzB5STDWoS13ihsSja5cmlCdu9BGLPo257Tytq+ZLT3SLkyD8aHNat1U3qGJyfABRm4eZaMTvXYuSzIquOTk+s1vAuFs52D1Jy1JBKSyNkdVO30B5HOPjSnpTT22l7H0qpcJWTtiimTvzZ154Gve0xLTWWHStxhZ8BZCCXwdcrPdCIahxuycNxRHMZQX1pOAkBY7JHJ/LTu1t/NbehCloUsEIM+h5J207bjdO10M7QeqxaNWWG7wOyMEIZZW1bhi9VSMkLHQt9mfh+dko9tlB5bP0GjtyZ1uCjHukAxc1NON5wZh2qOsTl2xh0+ScURc8TkQQhyTgoSRxFOXEdzllaIoCH049OQTBNs6ZjDjhBQcSuJ4gsUspoZJHeb6lXEB+Clo/X5CdTvtqLur6ICouTjX29Duj/oRz/c/uYvR6F1/v4v/yLob09S7+93cxpH/nLvrg+QAyImERRCSQHiV5gWcyYkJ6gubuNtx+cRe5ZDIA4MSX1CdBwXwSs8Inwo+3hZC5x7n3793Fu6c/AGSD4soACwAA"}}
#

import gzip
import json
import base64
import socket
import ssl
import re
import os
import boto3


# Parameters
DEBUG = True 

# Logstash instance (TCP input) 12347 is test Logstash queue
host = "172.31.8.61"
rawport = 12345

# SSL security
enable_security = False
ssl_port = 10515

# Config file location on S3
bucket = "config-awsvolks"
key = "knownGood.json"


metadata = {}


def lambda_handler(event, context):
    
    # if DEBUG : print(event)
       
    # Check prerequisites
    if host == "<your_logstash_hostname>" or host == "":
        raise Exception(
                "You must configure your Logstash hostname before starting this lambda function (see #Parameters section)")
    
    # Attach Logstash TCP Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    port = rawport
    if enable_security:
        s = ssl.wrap_socket(s)
        port = ssl_port

    try:
        s.connect((host, port))
    except:
        print("Error connecting to Logstash")
        exit(1)
    
    
    # get S3 config file
    # Example: {"knownGood" : [{"eventSource": "health.amazonaws.com"},{"log_entry_key": "RegExExpression"}]}
    # Config file defines regex for each field
    config = getS3ConfiFile(bucket, key)
    


    # Add the lambda context to event metadata
    metadata["aws"] = {}
    metadata["aws"]["function_name"] = context.function_name
    metadata["aws"]["function_version"] = context.function_version
    metadata["aws"]["invoked_function_arn"] = context.invoked_function_arn
    metadata["aws"]["memory_limit_in_mb"] = context.memory_limit_in_mb
    metadata["Enriched"] = {}
    metadata["Enriched"]["knownGood"] = "false"
    

    # decode and unzip cloudwatch data. Encoded payload can include multiple lines
    cw_data = event['awslogs']['data']
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload)
    payload = json.loads(uncompressed_payload)
    log_events = payload['logEvents']
    
    n=1
    for log_event in log_events:

        # fixes error with null value not enclosed in ""
        log_entry = log_event['message'].replace('none,', '"none",')
        log_entry = log_event['message'].replace('False,', '"False",')
        log_entry = log_event['message'].replace('True,', '"True",')
        
        # fixes Logstash debug error: logstash only hash map or arrays are supported
        log_entry = json.loads(log_entry)
        
        #print(log_entry['requestID'])
        if DEBUG: print(f"requestID:{log_entry['requestID']} eventSource:{log_entry['eventSource']} eventName:{log_entry['eventName']}")
        
        
        # merge metadata with event data
        log_entry = merge_dicts(log_entry, metadata)
        
        #print (log_entry)

        # check if log_entry field matches any defined regex for this field
        # Iterate through knownGood section within config file
        for knownGoodKeys in list(config['knownGood']):
            # get keys (returns array with single value)
            arr_key=list(knownGoodKeys)
            configkey = arr_key[0]
            configval = knownGoodKeys[configkey]
            
            # check each defined config statement
            if configkey in log_entry:
                #print (f"Checking if {configval} is in {log_entry[configkey]}")
                searchstring = log_entry[configkey]
                pattern = configval
                raw_pattern = r"{}".format(pattern)
                if re.search( raw_pattern, searchstring) : 
                    #print ("Found match in config file. Market as known good.")  
                    log_entry["Enriched"]["knownGood"] = "true"

   
        
        # Send to Logstash
        str_entry = json.dumps(log_entry)
        s.send((str_entry).encode("UTF-8"))
        if DEBUG: print (f"sent {n} logline(s)")
        n=n+1
        #print(str_entry)
    
    s.close()
    
    return {
        'statusCode': 200,
        'body': json.dumps('ok')
    }



def merge_dicts(a, b, path=None):
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                raise Exception(
                        'Conflict while merging metadatas and the log entry at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a
    
    
def getS3ConfiFile(bucket, key):
    # Read Configuration file stored in S3
    # Example: {"knownGood" : [{"eventSource": "health.amazonaws.com"},{"log_entry_key": "RegExExpression"}]}
    # Config file defines regex for each field

    s3 = boto3.client('s3')
    response = s3.get_object(Bucket=bucket, Key=key)
    config = response['Body'].read()
    config = json.loads(config)
    
    return (config)