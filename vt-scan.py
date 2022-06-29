# Super Simple S3 scanner,  @mrpogden 2022
#https://github.com/mrpogden/SuperSimpleS3Scanner

import requests
import json
import sys
from boto3 import client

def retrieve_objs():
    conn = client('s3')
    etag_list = []
    obj_key = []
    bucket_input = input("\nInput the name of the bucket you want to scan: ")
    for key in conn.list_objects(Bucket = bucket_input)['Contents']:
        obj_name = key['Key']
        obj_key.append(obj_name)
        s3_resp = conn.head_object(Bucket= bucket_input, Key=obj_name)
        etag_list.append(s3_resp['ETag'].strip('"'))
        etag_dict = dict(zip(obj_key, etag_list))
    return etag_dict;
Etags = retrieve_objs()

BASE_URL = 'https://www.virustotal.com/api/v3/files/'
headers = {
    'x-apikey' : '<INSERT API KEY HERE>',
    'Content-Type': 'application/json'
}

def vt_scan():

    for x,y in Etags.items():
        print('\n', x, '\n')
        r = requests.get(BASE_URL + y, headers=headers)
        data = r.json()
        #dumps the json object into an element
        json_str = json.dumps(data)

        #load the json to a string
        resp = json.loads(json_str)
        
        # validate clean
        if 'error' not in resp:
            #extract an element in the response
            for i in resp['data']['attributes']['last_analysis_stats']:
                print (i, ':', resp['data']['attributes']['last_analysis_stats'][i])
        else:
            #debug
            #print(resp)

        

vt_scan()

total_hashes = len(Etags)
total = str(total_hashes)
print(f'\n', "Total hashes scanned: " + total)
