#! /usr/bin/env python3
import subprocess
import os
import sys
from lib.interface import list_file_paths, SAMPLE_PATH  #, requests_manager
import configparser

MAX_QUERIES = 50000
batch_count = 0
# Not sure what this does, but it seems important
def system_cmd(cmd):
	return subprocess.call(cmd.split(' '))

if __name__ == '__main__':
	
	# Check for correct number of command line parameters and print help statement if not found
	if len(sys.argv) < 2:
		print("python3 batch.py [token]")
		sys.exit(1)

	# Chosen name for the folder in the results directory
	token = sys.argv[1]

	# Parse the batch section of the project configuration file
	try:
		config = configparser.ConfigParser()
		config.read("project.conf")

		pop_size = config['batch']['population_size']
		max_gen = config['batch']['max_num_generations']
		mut_rate = config['batch']['mutation_rate']
		stop_fit = config['batch']['fitness_threshold']
		folder = config['batch']['samples_folder']
	except:
		print("Check the batch section of project.conf and try again.")
		sys.exit(1)

	# List all of the files in the directory that are to be run using batch
	try:
		batch_folder_path = os.path.join(SAMPLE_PATH,folder)
		sample_paths = list_file_paths(batch_folder_path)
	except IOError:
		print("There was a problem reading in samples from the directory chosen")
		sys.exit(1)

	
	# For each file in the list, run a gp process for it
	for sample in sample_paths:

		# Check the number of classifier queries (to prevent sending more than allowed)
		if batch_count >= MAX_QUERIES:
			print("Reached %d queries, quit.", MAX_QUERIES)
			sys.exit(1)
		
		fileName = folder + '/' + sample

		# Call the gp code from the command line
		sys.stdout.flush()
		cmd = "./gp.py %s %s %s %s %s %s" % (pop_size, max_gen, mut_rate, stop_fit, fileName, token)
		try:
			print(cmd)
			subprocess.call(cmd.split(' '))
		except (KeyboardInterrupt, error):
			print("Error when trying to run GP")
			break
		
		# Something to do with keeping track of the queries...(world's worst system to track queries)
		results_dir = list_file_paths("results/%s/%s" % (token, fileName.split('/')[1]))
		#print(results_dir)
		file_string = results_dir[0]
		#print(file_string)
		num_string = file_string[10:]
		#print(num_string)
		batch_count += int(num_string)
		print("Batch count: ", batch_count)
	
