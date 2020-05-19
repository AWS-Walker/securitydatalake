import json
import socket
import ssl
import re
import os


# Parameters
DEBUG = True

# Logstash instance (TCP input)
host = "172.31.8.61"
rawport = 12346

# SSL security
enable_security = False
ssl_port = 10515

metadata = {}




def lambda_handler(event, context):
    
    if DEBUG : print(event)
       
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

    s.connect((host, port))
    
    # Add the context to meta
    metadata["aws"] = {}
    metadata["aws"]["function_name"] = context.function_name
    metadata["aws"]["function_version"] = context.function_version
    metadata["aws"]["invoked_function_arn"] = context.invoked_function_arn
    metadata["aws"]["memory_limit_in_mb"] = context.memory_limit_in_mb
    
    metadata["aws"]["time"] = event["time"]   
    metadata["aws"]["account"] = event["account"]   
    metadata["aws"]["region"] = event["region"]   
    
    # Take GuardDuty event and merge with metadata
    log_entry = merge_dicts(event["detail"], metadata)
    
    
    # Send to Logstash
    str_entry = json.dumps(log_entry)
    s.send((str_entry + "\n").encode("UTF-8"))
    
    
    
    
    
    
    
    
    return {
        'statusCode': 200,
        'body': json.dumps(log_entry)
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
    