from lib.malware_score_wrapper import get_score
import pickle

# Function to calculate and return the fitness score of each variant 
# Work-in-progress fitness function only considers the classifier's score (not ideal)
# Possible factors to include:
#	- whether the operation performed is generally good or bad
#	- the number of total operations performed on that variant since it split from the original sample
#	- difference in bytes to the original sample
#	- difference in bytes to the other variants 
#	- other?

# Goal is to achieve the highest score possible (high score = more benign)
def get_fitness(filepath):

	# Get the score from the classifier
	score = 1 - get_score(filepath) 
	
	# Fake score to avoid querying the classifier while testing other parts of code
	#import random
	#score = random.randint(1,10)

	return score

 
