#! /usr/bin/env python3
import logging
import random
import pickle
import os
import sys
import getopt
import copy
import pdb
import warnings
import lief

from lib.interface import get_bytez, touch, bytez_to_binary, write_to_file, SAMPLE_PATH
from lib.mutations2 import MalwareManipulator, modify_without_breaking, identity, mutate
from lib.malware_score_wrapper import get_score, get_label, get_binary_label
from lib.fitness import get_fitness
from lib.interface import setup_logging, LOW_SCORE, finished_flag, result_flag, error_flag, visited_flag
from lib.variant import Variant
import lib.interface as interface


class GP:
	def __init__(self, pop_size, max_gen, mut_rate, stop_fitness, start_file_name, token, results_dir, file_dir, fitness_func, seed, logger):	
		# Initialize the parameters
		self.pop_size = pop_size
		self.max_gen = max_gen
		self.mut_rate = mut_rate
		self.stop_fitness = stop_fitness
		self.start_file_name = start_file_name
		self.token = token
		self.results_dir = results_dir
		self.file_dir = file_dir
		self.fitness_func = fitness_func
		self.seed = seed
		self.logger = logger
		self.start_bytez = get_bytez(start_file_name)

		# Calculate the fitness of the original sample and create a variant object from it (could use a new name for variant class...)
		path = os.path.join(SAMPLE_PATH,start_file_name)
		self.start_fitness = fitness_func(path)
		self.logger.info("Starting fitness score is %s" % str(self.start_fitness))
		self.start_variant = Variant(self.start_bytez)
		self.start_variant.fitness_score = self.start_fitness #This seems very messy...(need to work on the constructor though)
		self.start_variant.fitness_trace.append(self.start_fitness) #Also very messy way to add to the fitness trace, but oh well

		# If no seed was provided, choose a random integer between 1 and 10,000
		if self.seed == None:
			seed = random.randint(1,10000)

		# Regardless of if a seed was provided, seed the generator 
		random.seed(seed)

		# Create a file in the results directory for that sample with the seed used, so that everything could be repeated (even if a seed was provided)
		seed_file_name = "Seed=" + str(seed)
		seed_file_name_path = os.path.join(self.file_dir, seed_file_name)
		touch(seed_file_name_path)
#****************************************************************************************************************************************************************************
	# Saves the population (array of variant objects) to a pickle file, so that you can easily access information about that generation in the interpreter
	def save_population_to_pickle(self):
		# Currently saves only the last generation to a pickle (and saves it to the variants subfolder)
		folder = os.path.join(self.file_dir, "variants")
		population_path = os.path.join(folder,"generation_%d.pickle" % self.generation)
		pickle.dump(self.population, open(population_path, "wb" ))
#****************************************************************************************************************************************************************************
	# Saves all of the variants in the population (and their corresponding traces) to files
	def save_variants_to_files(self):
		folder = "variants/generation_%d" % (self.generation)
		folder = os.path.join(self.file_dir, folder)
		if not os.path.isdir(folder):
			os.makedirs(folder)

		# Loop for actually writing the variants to files
		for j in range(len(self.population)):
			# Name the variant based on it's number in the population and create a path for it
			variant_name = "%d.exe" % (j)
			path = os.path.join(folder, variant_name)
			# Save the variant to file and add the path to the list
			write_to_file(self.population[j].bytez,path)
			# Add a suffix to the file path for the trace, save a pickle of the trace array there (kind of redundant but oh well)
			trace_path = path + ".trace"
			pickle.dump(self.population[j].trace, open(trace_path, "wb" ))
#****************************************************************************************************************************************************************************
	# Loads a variant from the past, but may not have been extensively tested
	def load_variant(self, gen, vid):
		path = "variants/generation_%d/%d.exe" % (gen, vid)
		path = os.path.join(self.file_dir, path)

		with open( path, 'rb') as infile:
			bytez = infile.read()
	
		trace_path = path + ".trace"
		trace = pickle.load(open(trace_path, "rb" ))
		variant = Variant(bytez)
		variant.trace = trace
		return variant
#****************************************************************************************************************************************************************************
	# Get the fitness scores for the entire population, adds the scores both to the appropriate variant object AND stores them in an array of fitness scores
	def population_fitness(self):
		folder = "generation_%d" % (self.generation)
		base_path = os.path.join(file_dir,"variants",folder)
		scores = []
		for i in range(self.pop_size):
			name = "%d.exe" % i
			path = os.path.join(base_path,name)
			variant_fitness = fitness_func(path)
			scores.append(variant_fitness)
			self.population[i].fitness_score = variant_fitness
			self.population[i].fitness_trace.append(variant_fitness)
			self.logger.info("Variant %d - Fitness Score: %s" % (i,str(variant_fitness)))
		return scores
#****************************************************************************************************************************************************************************
	# Core method of the class that actually runs the GP process
	def run(self):
		print("Running GP process...")
		self.logger.info("Starting a gp task...")
		
		# Populate the first generation with variants of the original sample
		self.population = self.get_init_pop()
		self.generation = 1

		# Loop to repeat for each generation until the specified max generation is reached (or the process is halted for another reason)
		while self.generation <= self.max_gen:
			self.logger.info("There are %d variants in generation %d." % (len(self.population), self.generation))
			
			# Save the entire generation to files (at this point, all of the variants have the same fitness score, which is the score of the o.g. sample)
			self.save_variants_to_files()	

			# Calculate the scores for the entire generation (assigns the correct fitness score to each variant)
			scores = self.population_fitness() 

			# Save the generation to a pickle file (can't be done at the same time as the previous save because the fitness scores have to be updated first)
			# Uncomment (and switch with the line later on) in order to save every generation to a pickle instead of just the last one
			#self.save_population_to_pickle()
			
			self.logger.info("Fitness scores: %s" % scores)
			self.logger.info("Sorted fitness: %s" % sorted(scores, reverse=True))
			
			# If the best score in the generation is greater than the desired fitness threshold, the process will stop
			if max(scores) > self.stop_fitness:
				self.best_score = max(scores)
				self.logger.info("Already got a high score [%f]>%f variant, break the GP process." % (max(scores), self.stop_fitness))
				touch(os.path.join(self.file_dir, finished_flag))
				break
			# Else if the process reaches the max generation without having stopped, it halts and records the best variant so far
			elif self.generation == max_gen:
				self.logger.info("Failed at max generation.")
				if max(scores) >= self.start_fitness: #switched seed_fitness to start_fitness...
					best_gen, best_vid, self.best_score = self.get_best_variant(1, self.generation)
					self.logger.info("Most promising variant was: %s of %d:%d" % (str(self.best_score), best_gen, best_vid))
				break

			# Selects the best variants and disposes of any with scores of LOW_SCORE (but without an oracle nothing is ever LOW_SCORE...)
			self.population = self.select()
			self.logger.info("After selecting the good variants and replacing the bad ones, we have %d variants in population." % len(self.population))
			self.logger.info("Beginning mutations for generation %d..." % (self.generation+1))
			
			# Performs the mutations to create the variants in the next generation
			for i in range(len(self.population)):
				mutate(self.population[i],i)
			
			# Increment the generation counter 
			self.generation = self.generation + 1

		# Information recorded if the max generation is reached
		self.logger.info("Stopped the GP process with max fitness %s." % str(self.best_score))
				
		# Moved this from every generation until the end, because we really only need to save the final generation (includes all of the previous ones)
		# Also saves to the main results folder for this variant too instead of the subdirectory where it saved before
		self.save_population_to_pickle()

		touch(os.path.join(self.file_dir, result_flag % self.best_score))
		touch(os.path.join(self.file_dir, "API_calls=%d" % interface.count))
		return True
#****************************************************************************************************************************************************************************
	# Method to populate the first generation of variants
	def get_init_pop(self):
		population = []
		count = 0
		while len(population) < int(self.pop_size):
			new_variant = copy.deepcopy(self.start_variant)
			mutate(new_variant, count)
			population.append(new_variant)
			count += 1
		return population
#****************************************************************************************************************************************************************************
	# Method to find the best variant between a specified start and end generation, records the generation, score, and variant ID of that variant
	def get_best_variant(self, start_gen, end_gen):
		best_gen = 1
		best_vid = 0
		best_score = LOW_SCORE
		return best_gen, best_vid, best_score
		for gen in range(start_gen, end_gen+1):
			scores = self.fitness_scores[gen]   # BUG THAT NEEDS TO BE FIXED....
			if max(scores) > best_score:
				best_score = max(scores)
				best_gen = gen
				best_vid = scores.index(best_score)
		#return best_gen, best_vid, best_score
		
#****************************************************************************************************************************************************************************
	# Method to select the best variants from a generation that should be mutated and move on to the next generation (fairly useless right now, needs work)
	def select(self):		
		next_gen = []
		self.logger.info("Selecting the best variants...")
		for variant in self.population:
			if variant.fitness_score == LOW_SCORE:      # We're not going to have any LOW_SCOREs unless malice is lost...which we wouldn't know without an oracle...            
				if self.generation == 1:
					self.logger.info("Ignored a variant with low score, replace with original file.")
					new_variant = copy.deepcopy(self.start_variant)	#Deepcopy b/c it's the original
					next_gen.append(new_variant)
				# If a variant NOT from generation 1 is found to have LOW_SCORE, it has a 1 in 3 chance of either being replaced with the o.g. sample, the best from the current
				# generation, or the best variant from all of the generations. This doesn't ever actually happen in the current version of the program...
				else:
					choice = random.choice(['start', 'last_gen_best', 'historic_best'])
					if choice == "start":
						self.logger.info("Ignored a variant with low score, replace with original file.")
						new_variant = copy.deepcopy(self.start_variant)	#Deepcopy b/c it's the original
						next_gen.append(new_variant)
					elif choice == "last_gen_best":
						best_gen, best_vid, best_score = self.get_best_variant(self.generation-1, self.generation-1)
						best_variant = self.load_variant(best_gen, best_vid)
						next_gen.append(best_variant)
						self.logger.info("Ignored a variant with low score, replace with best variant in last generation[%d, %d]." % (best_gen, best_vid))
					elif choice == "historic_best":
						best_gen, best_vid, best_score = self.get_best_variant(1, self.generation-1)
						best_variant = self.load_variant(best_gen, best_vid)
						next_gen.append(best_variant)
						self.logger.info("Ignored a variant with low score, replace with best variant in historic generation[%d, %d]." % (best_gen, best_vid))
			# If the variant does NOT have LOW_SCORE, then it is chosen to mutate and move on to the next generation
			else:
				self.logger.info("Selected a file with score %s" % str(variant.fitness_score))
				next_gen.append(variant)		
		return next_gen
	
#*************************************************************************************************************************************
# Function to parse the command line parameters entered to run the process (could be better done like Weilin's was with flags)
def get_opt(argv):
	file_name = None
	stop_fitness = None
	pop_size = None
	mut_rate = None
	max_gen = None
	token = None
	help_msg = "gp.py <population size> <max generations> <mutation rate> <stop fitness score> <starting file name> <token> <optional-seed>" 
	
	# Checks to make sure there are the correct number of command line parameters entered. If not, prints out the necessary information
	if len(argv) < 7:
		print (help_msg)
		sys.exit(2)

	pop_size = int(argv[1])
	max_gen = int(argv[2])
	mut_rate = float(argv[3])
	stop_fitness = float(argv[4])
	start_file_name = argv[5]
	token = argv[6]

	# Checks to see if there was an optional cmd param specified to choose the seed for the random number generator
	if len(argv) == 8:
		seed = int(argv[7])
	else:
		seed = None
	return pop_size, max_gen, mut_rate, stop_fitness, start_file_name, token, seed
#*************************************************************************************************************************************
if __name__ == "__main__":
	# Get the command line parameters
	pop_size, max_gen, mut_rate, stop_fitness, start_file_name, token, seed = get_opt(sys.argv)

	# Create the directories for the results and the inner directory for the file-specific information
	results_dir = "results/%s/" % (token)
	if not os.path.isdir(results_dir):
		os.makedirs(results_dir)
	file_dir_name = start_file_name.split('/')[1]
	file_dir = "results/%s/%s/" % (token, file_dir_name)
		
	# If that results directory already exists, exit (this might have been left over from before...)
	if os.path.exists(file_dir):
		print("Stopped in GP because the file already exists.")
		sys.exit(0)

	if not os.path.isdir(file_dir):
		os.makedirs(file_dir)

	# Specify the fitness function to be used
	fitness_func = get_fitness

	# Setup all of the logging information
	log_file_path = os.path.join(file_dir,visited_flag)
	setup_logging(log_file_path)
	logger = logging.getLogger('gp.core  ')
	logger.info("Starting logging for a GP process...")

	# Try to run the program and if there's an exception, print out the least helpful error message possible
	gp = GP(pop_size, max_gen, mut_rate, stop_fitness, start_file_name, token, results_dir, file_dir, fitness_func, seed, logger)
	gp.run()
	print(interface.count)
