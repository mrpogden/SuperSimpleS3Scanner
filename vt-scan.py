import requests
import json
from boto3 import client
from boto3 import resource


#variables
BASE_URL = 'https://www.virustotal.com/api/v3/files/'
headers = {
    'x-apikey' : '<Insert API KEY from VT HERE>',
    'Content-Type': 'application/json'
}

bucket_input = input("\nInput the name of the bucket you want to scan: ")
quarantine_bucket = input("\nOptional!  Input the bucket you want to use for quarantine. leave blank for none: ")

def retrieve_objs():
    conn = client('s3')
    etag_list = []
    obj_key = []
#    bucket_input = 'my-vt-test-buck-101'my-vt-test-buck-101
    for key in conn.list_objects(Bucket = bucket_input)['Contents']:
        obj_name = key['Key']
        obj_key.append(obj_name)
        s3_resp = conn.head_object(Bucket= bucket_input, Key=obj_name)
        etag_list.append(s3_resp['ETag'].strip('"'))
        etag_dict = dict(zip(obj_key, etag_list))
    return etag_dict;
Etags = retrieve_objs()



def vt_scan():

    for x,y in Etags.items():
#        print('\n', x, '\n')
        r = requests.get(BASE_URL + y, headers=headers)
        data = r.json()
        #dumps the json object into an element
        json_str = json.dumps(data)

        #load the json to a string
        resp = json.loads(json_str)
        
        # validate clean
        if 'error' not in resp:
            if resp['data']['attributes']['last_analysis_stats']['malicious'] > 0:   #  Fine tune how sensitive the response should be.
                result = { x:y, 'report': {}}
                #extract an element in the response
                for i in resp['data']['attributes']['last_analysis_stats']:
                    z =  resp['data']['attributes']['last_analysis_stats'][i]
                    result ['report'][i] = z
                json_result = json.dumps(result, indent = 4)

                
            # Optional, SNS Notifcation when malicious file found               
#                sns = client('sns')
#                notify = sns.publish(
#                TopicArn='<OPTIONAL SNS ARN>',   
#                Message=json_result,
#                )
 
             # Optional, move malicious files to a seperate Quarantine bucket
        
             # Copy object to Quarantine bucket
#               print(bucket_input, quarantine_bucket)
                if not quarantine_bucket:
                    s3 = resource('s3')
                    copy_source = {
                    'Bucket': bucket_input,
                    'Key': x
                      }
 #                  print (copy_source)
                    s3.meta.client.copy(copy_source, quarantine_bucket, x)
            # Delete original object
                    s3c = client('s3')
                    s3c.delete_object(Bucket=bucket_input, Key=x)
                print (json_result)

        #else:
        #    #debug
        #    print(resp)
      
vt_scan()

total_hashes = len(Etags)
total = str(total_hashes)

print(f'\n', "Total objects scanned: " + total)
