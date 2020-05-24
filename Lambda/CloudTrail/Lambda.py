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
# STS auth to ES instead of us
# Find the right trigger batch size 
# single ES put or bulk?
# date in the index!!!!
# KMS
# set cloudwatch error if this lambda throws an error
# knownBad and complex filters (AND/OR)



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
bulkMessages = []
uploadType = "bulk"   # buld or single


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
    

# Indexing of a single document 
def indexDocElement(esClient, esIndex, jsonDoc):
    retval = {}
    retval['_shards'] = {}
    retval['_shards']['failed'] = 0
    try:
        retval = esClient.index(index=esIndex, body=jsonDoc)
        if DEBUG_ES: print(f"ReturnVal: {retval}")
    except:
        print("--- Error indexing the following doc ----")
        print(jsonDoc)
        print("--- End of index error dump ----")
    
    if retval['_shards']['failed'] > 0:
        print(f"ReturnVal: {retval['_index']} {retval['_shards']}")
    return retval


# Helper to index a bulk of documents
def indexDocElementBulk():
    print(f"Bulk indexing of {len(bulkMessages)} messages")
    
    for message in bulkMessages:
      yield {
          "_index": ES_INDEX,
          '_op_type': 'index',
          "_source": message,
      }    
    return


# string replace (all occurences, case insensitive)
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
    

# fix JSON bugs of CloudWatch   
def fixCloudWatchJson(CloudTrailMsg):

    CloudTrailMsgOrig = CloudTrailMsg
    CloudTrailMsg = ireplace('["]', '[""]', CloudTrailMsg)
    CloudTrailMsg = ireplace(',}', '}', CloudTrailMsg)
    CloudTrailMsg = ireplace(':"}', ':"DELETEME"}', CloudTrailMsg)
    CloudTrailMsg = ireplace("False,", '"false",', CloudTrailMsg)
    CloudTrailMsg = ireplace("True,", '"true",', CloudTrailMsg)
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
        if val == "DELETEME" or val == "" :
            fieldsToDelete.append(key)

    for key in fieldsToDelete:
        del CloudTrailMsgJson[key]
           
    return CloudTrailMsgJson   
    

# base64/gzip helper
def decodeAndUncompress(compressed_payload):
    compressed_payload = base64.b64decode(compressed_payload)
    uncompressed_payload = gzip.decompress(compressed_payload)
    return json.loads(uncompressed_payload)

# base64/gzip helper
def encodeAndCompress(payload):
    message_bytes = str(payload).encode('ascii')
    payload = base64.b64encode(message_bytes)
    payload = gzip.compress(payload)
    return payload
    

# merge two Python dictionaries
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
                        'Conflict while merging two dictionaries at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a
    
    
# fill global variable metadata with GeoIP information (MaxmindDB)
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


# check JSON message for a match in the knownGood configuatin file (field:regex)
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
    
    if DEBUG: print("-----------Kinesis Payload -------------")
    if DEBUG: print(event)
    noOfKinesisMsg = len(event['Records'])
    print (f"Received {noOfKinesisMsg} CloudWatch messages in Kinesis data stream")
    
    if DEBUG: print("-----------CloudWatch Payload -------------")
    n=0
    for KinesisEvent in event['Records']:
        n=n+1
        arrCloudWatch = decodeAndUncompress(KinesisEvent['kinesis']['data'])
        if DEBUG: print(arrCloudWatch)
        
        
        if DEBUG: print("-----------CloudTrail Payload-------------")
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
         
            if uploadType == "single":
                ret = indexDocElement(esClient, index, CloudTrailMsg)
                if DEBUG: print (f"Index Result: {ret['_shards']}")
            else:
                bulkMessages.append(CloudTrailMsg)
    
    
    # Send bulk messages to Elasticsearch
    if uploadType == "bulk":
        helpers.bulk(esClient,indexDocElementBulk())
    
    totalIndexCount = esClient.count(index=ES_INDEX)
    print (f"{n} Kinesis events received. {m} CloudTrail events parsed. Index size after: {totalIndexCount}")
    print (f"--- End of function execution at at {now.hour}:{now.minute}:{now.second} ---")
    
    if DEBUG: 
        print(f"=========={now.minute}:{now.second}=============")
    
    return {
        'statusCode': 200,
        'body': json.dumps('ok')
    }





