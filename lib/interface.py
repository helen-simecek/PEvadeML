import requests
import gzip
import json
import re
import sys
import os
import lief
import copy
import hashlib
import logging

# Common variables to be used througout the project
module_path = os.path.split( os.path.abspath( sys.modules[__name__].__file__ ) )[0]
SAMPLE_PATH = os.path.join(os.path.split(module_path)[0],"samples")
LOW_SCORE = 0
finished_flag = "evaded.flag"
visited_flag = "dev.log"
result_flag = "fitness_%.2f.flag"
error_flag = "error.flag"
count = 0		# Count is to keep track of classifier queries, would not always be necessary

# Define a custom exception (if the file cannot be retrieved)
class FileRetrievalFailure(Exception):
	pass

# Function to include the write metadata when a file is changed (I believe)
def touch(fname):
	try:
		os.utime(fname, None)
	except:
		open(fname, 'a').close()

# Function that take in a file name and returns the contents of that file in a bytestring
def get_bytez(file):	
	location = os.path.join(SAMPLE_PATH, file)  
	try:
		with open( location, 'rb') as infile:
			bytez = infile.read()
	except IOError:
		raise FileRetrievalFailure("Unable to read sha256 from {}".format(location) )

	return bytez

# Function that takes in a bytestring and returns in a lief binary form
# (was more practical when conversion involved more code...)
def bytez_to_binary(bytez):
	binary = lief.PE.parse(bytez)
	return binary

# Function that takes in a bytestring and filepath and creates a file from those bytes at that path (writes to an .exe file)
def write_to_file(bytez, file_path):
	binary = bytez_to_binary(bytez)
	binary.write(file_path)
	return

# Function to setup logging that will be shared between modules
def setup_logging(log_file_path):    
	logging.basicConfig(filename=log_file_path,
						filemode='a',
						format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
						level=logging.DEBUG,
						)                  
	logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(logging.ERROR)

# Takes in a directory name and an optional size limit
# Lists the file names in a folder and sorts that list to make it deterministic and returns
def list_file_paths(dir_name, size_limit=None):
	fnames = os.listdir(dir_name)
	fnames.sort()
	if size_limit:
		return fnames[:size_limit]
	else:
		return fnames



