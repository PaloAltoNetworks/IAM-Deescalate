import json
import os
import re
import logging

def loadFromJson(filepath):
    ''' Load a json file to an python object '''
    if not os.path.exists(filepath):
        logging.error('File %s does not exist' %filepath)
        exit()
    with open(filepath, newline='', encoding='utf-8') as fhand:
        try:
            return json.load(fhand)
        except json.decoder.JSONDecodeError as e:
            logging.error(e)
            return

def dumpToJson(obj, filePath, indent=None):
    ''' dump a python object to Json'''
    with open(filePath, 'w') as fp:
        json.dump(obj, fp, default=str, indent = indent)

principal_re = re.compile(r':\d{12}:(.+)')
def parse_principal_from_arn(arn):
    ''' parse out the principal part starting from user, role, or group from an input arn'''
    search = principal_re.search(arn)
    if search:
       return search.group(1).strip()

def check_boto3_response(resp):
    ''' check the response of boto3 APIs '''
    return 'ResponseMetadata' in resp and resp['ResponseMetadata']['HTTPStatusCode'] >= 200 and resp['ResponseMetadata']['HTTPStatusCode'] < 300
