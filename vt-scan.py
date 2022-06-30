import requests
import json
import sys
from boto3 import client

def retrieve_objs():
    conn = client('s3')
    etag_list = []
    obj_key = []
    bucket_input = input("\nInput the name of the bucket you want to scan: ")
#    bucket_input = 'my-vt-test-buck-101'
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
#        print('\n', x, '\n')
        r = requests.get(BASE_URL + y, headers=headers)
        data = r.json()
        #dumps the json object into an element
        json_str = json.dumps(data)

        #load the json to a string
        resp = json.loads(json_str)
        
        # validate cleaneiifcc
        if 'error' not in resp:
            if resp['data']['attributes']
            ['last_analysis_stats']['malicious'] < 3:   #  Fine tune how sensitive the response should be by the number of AV engines with a +tive hit.
                result = { x:y, 'report': {}}
                #extract elements in the response
                for i in resp['data']['attributes']['last_analysis_stats']:
                    z =  resp['data']['attributes']['last_analysis_stats'][i]
                    result ['report'][i] = z
                json_result = json.dumps(result, indent = 4)
                print (json_result)
        
        #else:
        #    #debug
        #    print(resp)
   
        

vt_scan()

total_objects = len(Etags)
total = str(total_objects)

print(f'\n', "Total objects scanned: " + total)
