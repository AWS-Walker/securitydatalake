# Prerequisites
# -------------
# Setup: CloudTrail > CloudWatch Subscription > Kinesis Streams > Lambda Trigger > Elasticsearch
# add geolite.py into root directory of Lambda function
# Layers: add layer "Layer ES" and "Layer GeoIP"
# Timeout: min 2min (if not working in bulk)
# Memory: typically used 90MB
# Permissions: Role (get kinesis records, write to ES)
# Upload S3 config file into S3 bucket and update bucket and file name to the config of this Lambda

# TO DO:
# Find the right trigger batch size 
# single ES put or bulk?
# date in the index!!!!
# KMS




import gzip
import json
import base64
import re
import os
import boto3
import datetime


# Elasticsearch 
import requests
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers 
import urllib3

# Maxmind
from geolite2 import geolite2

# Config file location on S3
bucket = "config-awsvolks"
key = "knownGood.json"



# Globals
DEBUG = False 
DEBUG_ES = False

# Elasticsearch Domain
ES_ENDPOINT = 'search-canva-gpqk7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com'
ES_INDEX = 'cloudtrail'

# Config file location on S3
bucket = "config-awsvolks"
key = "knownGood.json"

metadata = {}
metadata["Enriched"] = {}
metadata["Enriched"]["knownGood"] = "false"
metadata["geoip"] = {}



def getS3ConfiFile(bucket, key):
    s3 = boto3.client('s3')
    response = s3.get_object(Bucket=bucket, Key=key)
    config = response['Body'].read()
    config = json.loads(config)
    return (config)
    
    
def connectES(esEndPoint):
    if DEBUG_ES: print ('Connecting to the ES Endpoint {0}'.format(esEndPoint))
    try:
        esClient = Elasticsearch(
        hosts=[{'host': esEndPoint, 'port': 443}],
        http_auth=('volker', 'Password1!'),
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection)
        return esClient
    except Exception as E:
        print("Unable to connect to {0}".format(esEndPoint))
        print(E)
        exit(3)
    


def indexDocElement(esClient, esIndex, jsonDoc):
    # TEST ONLY jsonDoc='{"eventVersion": "1.05", "userIdentity": {"type": "AWSService", "invokedBy": "securityhub.amazonaws.com"}, "eventTime": "2020-05-21T03:49:02Z", "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole", "awsRegion": "us-east-2", "sourceIPAddress": "securityhub.amazonaws.com", "userAgent": "securityhub.amazonaws.com", "requestParameters": {"roleArn": "arn:aws:iam::861828696892:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub", "roleSessionName": "securityhub"}, "responseElements": {"credentials": {"accessKeyId": "ASIA4RKH6JM6DPYT3W26", "expiration": "May 21, 2020 4:49:02 AM", "sessionToken": "IQoJb3JpZ2luX2VjEMz//////////wEaCXVzLWVhc3QtMiJHMEUCIQDZb72g/z4UOsMlWLtoAyno6Jk545DwKGEjayPKRdUJwwIgRS/mJvISHj8BJWTH5TK6LZ66m2AgC8fKC+XcUa5XYvYqkgIIJRABGgw4NjE4Mjg2OTY4OTIiDNaouyzPFFXT2AKZWSrvAVAgKWprQ6DKQ0SuPO3cytAF9LWtoDaW4FArQuaMymjsxSfHS8fZ+SIIeSrJczg2/upmDGp3KfIUFLLOcTUMavMa3aRZgf1Rz7IZxh8WT753eXgkD8gW30CCJME/o5vxeXKZkRA+4xAvblC/C2fDgXIDw/CX3w7XxxdbK6KJP3onKx/hJlw3McnVAdIDIqZO40l7NJW9rVLomBG5ln6R/PBvYf2LCTEKKCB7dZ49JOKBib8yd3rDy4JsUwRQPFaHYgk57cWEB5pPfi1YIS/3nI71VPRw2RBeUMHG/WkJIP1RWuwmxM+RVx7GxHfC1rpbMK70l/YFOoUCovD5sdI4oKejlMkKoE7E9QeuKnUZVPPN/9JxSt3jkxtXiQ+/9V563MgcXJ0Rmde0mxjndlNW+xn5OEIqwq8lsq9Ni49b05RjtL1JL4CYB8PQnspMglnQmxVAJrj13z1aaOOYTUg4FSQnD4jNkaA1wFFwUulOhFkaRyHnAbWltIN0m0r1IbQCTYcInxXp82GxyTaR/Evw6orazXQDpZinVlsh8/+q0HAtpgh5JRoFlGqSVopBmHj4kYr7ENiSQSO7f7LyxocfHxYHNU+6y6BswSmxnbMYcII5WmLRrHZJe3rI0haOF1bc1YQs90NRbk2g0EN+WgURp29jk57yb0dra4I4/YEM"}, "assumedRoleUser": {"assumedRoleId": "AROA4RKH6JM6G4PBGAVG7:securityhub", "arn": "arn:aws:sts::861828696892:assumed-role/AWSServiceRoleForSecurityHub/securityhub"}}, "requestID": "31a72682-1202-4180-8a84-cf9dfc770807", "eventID": "6e388847-ffc1-4466-9167-30918d79db9c", "resources": [{"ARN": "arn:aws:iam::861828696892:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub", "accountId": "861828696892", "type": "AWS::IAM::Role"}], "eventType": "AwsApiCall", "recipientAccountId": "861828696892", "sharedEventID": "ba9ccd97-37da-4a45-84bc-9e8ffaf3dc6f"}'
    retval = esClient.index(index=esIndex, body=jsonDoc)
    if DEBUG_ES: print(f"ReturnVal: {retval}")
    
    if retval['_shards']['failed'] > 0:
        print(f"ReturnVal: {retval['_index']} {retval['_shards']}")
    return retval


def ireplace(old, new, text):
    # change not one, but all occurrences of old with new - in a case insensitive fashion
    idx = 0
    while idx < len(text):
        index_l = text.lower().find(old.lower(), idx)
        if index_l == -1:
            return text
        text = text[:index_l] + new + text[index_l + len(old):]
        idx = index_l + len(new) 
    return text
    
    
def fixCloudWatchJson(CloudTrailMsg):

    # repair crappy JSON format of CloudWatch
    CloudTrailMsgOrig = CloudTrailMsg
    CloudTrailMsg = ireplace('["]', '[""]', CloudTrailMsg)
    CloudTrailMsg = ireplace(',}', '}', CloudTrailMsg)
    CloudTrailMsg = ireplace(':"}', ':"DELETEME"}', CloudTrailMsg)

    CloudTrailMsg = ireplace("False,", '"DELETEME",', CloudTrailMsg)
    CloudTrailMsg = ireplace("True,", '"DELETEME",', CloudTrailMsg)
    CloudTrailMsg = ireplace("null,", '"DELETEME",', CloudTrailMsg)
    CloudTrailMsg = ireplace("none,", '"DELETEME",', CloudTrailMsg)
    
    
    CloudTrailMsgJson = {}
    
    
    try:
        CloudTrailMsgJson = json.loads(CloudTrailMsg)
    except:
        print("----Json decode error dump start ---")
        print(CloudTrailMsg)
        print("----Json decode error dump end ---")
    
    
    # Remove empty fields. Don't replace with empty string as they often are dics in ES which causes errors
    fieldsToDelete = []

    for key, val in CloudTrailMsgJson.items():
        if val == "DELETEME":
            fieldsToDelete.append(key)

    for key in fieldsToDelete:
        del CloudTrailMsgJson[key]
           
    return CloudTrailMsgJson   
    
    
def decodeAndUncompress(compressed_payload):
    compressed_payload = base64.b64decode(compressed_payload)
    uncompressed_payload = gzip.decompress(compressed_payload)
    return json.loads(uncompressed_payload)


def encodeAndCompress(payload):
    message_bytes = str(payload).encode('ascii')
    payload = base64.b64encode(message_bytes)
    payload = gzip.compress(payload)
    return payload
    
    
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
    
    
def getGeoIp(sourceIPAddress):
    
    try:
        reader = geolite2.reader()
        geo_loc = reader.get(sourceIPAddress)  
    except:
        return
    
    try:
        metadata["geoip"]["city_name"] = geo_loc['city']['names']['en']
    except:
        metadata["geoip"]["city_name"] = 'Unidentified'
    try:
        metadata["geoip"]["country_name"] = geo_loc['country']['names']['en']
    except:
        metadata["geoip"]["country_name"] = 'Unidentified'
    try:
        metadata["geoip"]["latitude"] = str(geo_loc['location']['latitude'])
        metadata["geoip"]["longitude"] = str(geo_loc['location']['longitude'])
        metadata["geoip"]["country_code3"] = str(geo_loc['country']['iso_code'])
        metadata["geoip"]["continent_code"] = str(geo_loc['continent']['code'])
    except:
        metadata["geoip"]["latitude"] = '0'
        metadata["geoip"]["longitude"] = '0'
        metadata["geoip"]["country_code3"] = ""
        metadata["geoip"]["continent_code"] = ""
    try:
        metadata["geoip"]["postal_code"] = str(geo_loc['postal']['code'])
        metadata["geoip"]["region_code"] = str(geo_loc['subdivisions'][0]['iso_code'])
        metadata["geoip"]["region_name"] = str(geo_loc['subdivisions'][0]['names']['en'])
        metadata["geoip"]["timezone"] = str(geo_loc['location']['time_zone'])
    except:
        metadata["geoip"]["postal_code"] = ""
        metadata["geoip"]["region_code"] = ""
        metadata["geoip"]["region_name"] = ""
        metadata["geoip"]["timezone"] = ""        
            
    return 


def checkForKnownGood(config, message):
    knownGood = False
    
    # check if log_entry field matches any defined regex for this field
    # Iterate through knownGood section within config file
    for knownGoodKeys in list(config['knownGood']):
        # get keys (returns array with single value)
        arr_key=list(knownGoodKeys)
        configkey = arr_key[0]
        configval = knownGoodKeys[configkey]
        
        # check each defined config statement
        if configkey in message:
            #print (f"Checking if {configval} is in {message[configkey]}")
            searchstring = message[configkey]
            pattern = configval
            raw_pattern = r"{}".format(pattern)
            if re.search( raw_pattern, searchstring) : 
                #print ("Found match in config file. Market as known good.")
                knownGood = True
    return knownGood
    
    
    
#
# main
#

def lambda_handler(event, context):
           
    now = datetime.datetime.now()
    indexdate = now.strftime("%Y-%m-%d")
    index=ES_INDEX+'-'+indexdate
    
    
    # Connect to Elasticsearch
    esClient = connectES(ES_ENDPOINT)
    
    # get S3 config file
    config = getS3ConfiFile(bucket, key)
    
    if DEBUG: print("-----------Kinesis-------------")
    if DEBUG: print(event)
    noOfKinesisMsg = len(event['Records'])
    print (f"Received {noOfKinesisMsg} CloudWatch messages in Kinesis data stream")
    
    if DEBUG: print("-----------CloudWatch-------------")
    n=0
    for KinesisEvent in event['Records']:
        n=n+1
        arrCloudWatch = decodeAndUncompress(KinesisEvent['kinesis']['data'])
        if DEBUG: print(arrCloudWatch)
        
        
        if DEBUG: print("-----------CloudTrail-------------")
        noOfCloudWatchMsg = len(arrCloudWatch['logEvents'])
        print (f"Received {noOfCloudWatchMsg} events in CloudWatch message no.{n} ")
        
        m=0
        for CloudTrailEvent in arrCloudWatch['logEvents']:
            m=m+1

            CloudTrailMsg = fixCloudWatchJson(CloudTrailEvent['message'])   
            if 'sourceIPAddress' in CloudTrailMsg: getGeoIp(CloudTrailMsg['sourceIPAddress'])
            CloudTrailMsg = merge_dicts(CloudTrailMsg, metadata)
 
            if checkForKnownGood(config, CloudTrailMsg):
                CloudTrailMsg["Enriched"]["knownGood"] = "true"

            if DEBUG: print(f"CloudTrail event #{n}/{m}: ")
            if DEBUG: print(CloudTrailMsg)
         
            # Send Message to Elasticsearch
            ret = indexDocElement(esClient, index, CloudTrailMsg)
            if DEBUG: print (f"Index Result: {ret['_shards']}")
            
            
    print (f"{n} Kinesis events received. {m} CloudTrail events parsed at {now.hour}:{now.minute}:{now.second}")
    

    if DEBUG: 
        print(f"=========={now.minute}:{now.second}=============")
    
    
    
    
    # Test Event
    RunTest = False
    if RunTest :
        print(f"==========Test Event Sent=============")
        testevent = '{"eventVersion": "0.01","eventTime": "x","eventSource": "LambdaTest","eventName": "LambdaTest","Enriched": {"knownGood": "true"}, "responseElements": None}'
        testevent = fixCloudWatchJson(testevent)  
        testevent['eventTime'] = now.strftime("%Y-%m-%d"+"T"+"%H:%M:%SZ")
        print(testevent)
        indexDocElement(esClient, index, testevent)
    
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }





