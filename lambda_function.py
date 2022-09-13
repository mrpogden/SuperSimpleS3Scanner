import json
import urllib.parse
import boto3
import requests
import sys

BASE_URL = 'https://www.virustotal.com/api/v3/files/'
headers = {
    'x-apikey' : 'INSERT API KEY HERE',
    'Content-Type': 'application/json'
}

quarantine_bucket = 'INSERT QUARANTINE BUCKET NAME'

print('Loading function')

s3 = boto3.client('s3')

def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])
        etag = response['ETag'].strip('"')
        r = requests.get(BASE_URL + etag, headers=headers)
        data = r.json()
        #dumps the json object into an element
        json_str = json.dumps(data)

        #load the json to a string
        resp = json.loads(json_str)
        
        # validate clean
        if 'error' not in resp:
            if resp['data']['attributes']['last_analysis_stats']['malicious'] > 3:   #  Fine tune how sensitive the response should be.
                result = { key:etag, 'report': {}}

            #extract elements in the response
                for i in resp['data']['attributes']['last_analysis_stats']:
                    z =  resp['data']['attributes']['last_analysis_stats'][i]
                    result ['report'][i] = z
                json_result = json.dumps(result, indent = 4)

            # Send any findings to SNS
                sns = boto3.client('sns')
                notify = sns.publish(
                TopicArn='INSERT ARN FOR SNS TOPIC',   
                Message=json_result,   
                )
                
            # Copy object to Quarantine
                client = boto3.client('s3')
                response = client.list_objects_v2(Bucket=bucket, Prefix = key)
                source_key = response["Contents"][0]["Key"]
                copy_source = {
                'Bucket': bucket,
                'Key': key
                    }
                client.copy_object(Bucket = quarantine_bucket, CopySource = copy_source, Key = key)
            #Delete original object after move to Quarantine
                client.delete_object(Bucket = bucket, Key = key)

                print (json_result)

            else:
                return "clean";
    except Exception as e:
        print(e)
        print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
        raise e