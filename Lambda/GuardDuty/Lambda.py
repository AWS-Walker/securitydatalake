# Lambda to receive GuardDuty messages from CloudWatch rule
# Expects one event at the time

import json
import re
import os
import datetime

# Elasticsearch libraries
import requests
from elasticsearch import Elasticsearch, RequestsHttpConnection, helpers 
import urllib3


# Globals
DEBUG = False 
metadata = {}

# Elasticsearch Domain
ES_ENDPOINT = 'search-canva-gpqk7fy3xguvkfnhczlw3yxqui.us-east-2.es.amazonaws.com'
ES_INDEX = 'guardduty'

# unique field of event message that is getting indexed (event["Details"])
uniqueIdFieldName = "id"            


# Merge two dictionaries
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



def connectES(esEndPoint):
    if DEBUG: print ('Connecting to the ES Endpoint {0}'.format(esEndPoint))
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
def indexDocElement(esClient, esIndex, uniqueId, jsonDoc):
    retval = {}
    retval['_shards'] = {}
    retval['_shards']['failed'] = 0
    
    uniqueIdValue = jsonDoc[uniqueId]

    try:
        retval = esClient.index(index=esIndex, body=jsonDoc, id=uniqueIdValue)     
        if DEBUG: print(f"ReturnVal: {retval}")
    except Exception as inst:
        print("--- Error indexing the following doc ----")
        #print(jsonDoc)
        print (type(inst))     # the exception instance
        print (inst.args)      # arguments stored in .args
        print (inst)           # __str__ allows args to be printed directly
        print("--- End of index error dump ----")
    
    if retval['_shards']['failed'] > 0:
        print(f"ReturnVal: {retval['_index']} {retval['_shards']}")
    return retval

   
   

#
# main
#

# fix index with id
# fix cloudwatch event or only detail?


def lambda_handler(event, context):
    
    #if DEBUG : print(event)
    
    now = datetime.datetime.now()
    indexdate = now.strftime("%Y-%m-%d")
    index=ES_INDEX+'-'+indexdate
    
    
    # Connect to Elasticsearch
    esClient = connectES(ES_ENDPOINT)

   
    # Add the context to meta
    metadata["Lambda"] = {}
    metadata["Lambda"]["function_name"] = context.function_name
    metadata["Lambda"]["function_version"] = context.function_version
    metadata["Lambda"]["invoked_function_arn"] = context.invoked_function_arn
    metadata["Lambda"]["memory_limit_in_mb"] = context.memory_limit_in_mb
    
    metadata["Lambda"]["time"] = event["time"]   
    metadata["Lambda"]["account"] = event["account"]   
    metadata["Lambda"]["region"] = event["region"]   
    
    # Take GuardDuty event and merge with metadata
    jsonEvent = merge_dicts(event["detail"], metadata)
    
    
    # Index document
    ret = indexDocElement(esClient, index, uniqueIdFieldName, jsonEvent)
    if DEBUG: print (f"Index Result: {ret['_shards']}")

    

    return {
        'statusCode': 200,
        'body': json.dumps("Ok")
    }




 