
# Define a variant object that make up the population of the gp process
# Each variant consists of a byte string, a trace, and a fitness score (and now a trace of prior fitness scores)
# Note - this could probably be moved into interface.py since it's shared between modules
class Variant(object):
	bytez = ""
	trace = []
	fitness_score = None
	fitness_trace = []

	def __init__(self,bytez):
		self.bytez = bytez
		self.trace = []
		self.fitness_score = 0
		self.fitness_trace = []		# Used to keep track of the fitness scores of a variant across generations





