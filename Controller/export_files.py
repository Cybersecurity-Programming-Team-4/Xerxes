#!/usr/bin/python3

# This code uploads output files to a Google storage bucket to free memory on the client machine

from google.cloud import storage
from google import cloud
import logging
import os
from GLOBALS import *

BUCKET = 'xerxes-output-files'
PROJECT = 'xerxes-163204'

def exportFiles():
    exFiles = os.listdir(OUT_DIR)
    try:
        client = storage.Client(PROJECT)
        bucket = client.get_bucket(BUCKET)
        for f in exFiles:
            blob = storage.Blob(f, bucket)
            fp = OUT_DIR + '/' + f
            blob.upload_from_filename(fp, 'text/plain', client) # Upload to storage bucket
            os.remove(fp)
    except cloud.exceptions as e:
        logging.exception('Could not instantiate cloud storage objects!', e)
    except IOError as e:
        logging.exception('Log/Output file open error!', e)
    except OSError as e:
        logging.exception('Could not remove file!', e)
