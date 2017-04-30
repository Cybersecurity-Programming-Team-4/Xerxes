#!/usr/bin/python3

# This code uploads output files to a Google storage bucket to free memory on the client machine

from google.cloud import storage
from google import cloud
import logging
import os
import sys
sys.path.append('/home/shawn/Xerxes')
from GLOBALS import *

def exportFiles():
    exFiles = os.listdir(OUT_DIR)
    try:
        client = storage.Client(PROJECT_ID)
        bucket = client.get_bucket(BUCKET)
        for f in exFiles:
            blob = storage.Blob(f, bucket)
            fp = OUT_DIR + '/' + f
            blob.upload_from_filename(fp, 'text/plain', client) # Upload to storage bucket
            os.remove(fp)
    except google.cloud.exceptions.GoogleCloudError as e:
        logging.error('Log/Output file open error!'.format(e))
    except IOError as e:
        logging.error('Log/Output file open error!'.format(e))
    except OSError as e:
        logging.error('Could not remove file! {}'.format(e))

def exportFile(f, content_type):
    try:
        client = storage.Client(PROJECT_ID)
        bucket = client.get_bucket(BUCKET)
        blob = storage.Blob(f, bucket)
        blob.upload_from_filename(f, content_type, client)  # Upload to storage bucket
        os.remove(f)
    except google.cloud.exceptions.GoogleCloudError as e:
        logging.error('Log/Output file open error!'.format(e))
    except IOError as e:
        logging.error('Log/Output file open error!'.format(e))
    except OSError as e:
        logging.error('Could not remove file! {}'.format(e))

def exportLogs():
    logFiles = os.listdir(LOG_DIR)
    try:
        client = storage.Client(PROJECT_ID)
        bucket = client.get_bucket(BUCKET)
        for f in logFiles:
            blob = storage.Blob(f, bucket)
            fp = LOG_DIR + '/' + f
            blob.upload_from_filename(fp, 'text/plain', client)  # Upload to storage bucket
            os.remove(fp)
    except google.cloud.exceptions.GoogleCloudError as e:
        logging.error('Log/Output file open error!'.format(e))
    except IOError as e:
        logging.error('Log file open error!'.format(e))
    except OSError as e:
        logging.error('Could not remove file! {}'.format(e))