import pickle
import sys
import operator
import os


# The score you want each mutation to start at (default = 0, positive -> good, negative -> bad)
starting_score = 0

# Create an empty dictionary to hold mutation and associated score
mutations_dictionary = {}
frequency_dictionary = {}

# List of all possible mutations (can easily be updated)
mutations_list = ['overlay_append','imports_append','section_rename','section_add','section_append','create_new_entry','upx_pack','upx_unpack', 'remove_signature', 'break_optional_header_checksum']

# Initialize the mutations dictionary with the desired mutation and starting score
for mutation in mutations_list:
	mutations_dictionary[mutation] = starting_score
	frequency_dictionary[mutation] = 0

# CMD parameter to the batch folder of results
file_stem = sys.argv[1]

hash_list = os.listdir(file_stem)

for hash in hash_list:
	file_path = file_stem + "/" + hash + "/" + "variants"
	max_generation = len(os.listdir(file_path)) - 1
	print("max generation: ",max_generation)
	file_path = file_path + "/" + "generation_%d.pickle" % (max_generation)
	print(file_path)
	

	population = pickle.load(open(file_path,'rb'))

	# For each variant in the population...
	for variant in population:

		# Load the array of fitness scores and mutations
		variant_trace = variant.trace
		print("Variant trace",variant_trace)
		variant_scores = variant.fitness_trace
		print("Variant scores", variant_scores)

		# For each mutation made...
		for i in range(len(variant_trace)):
			#Calculate the difference in fitness scores
			difference = variant_scores[i+1] - variant_scores[i]
			print("Difference: ", difference)

			mutation = variant_trace[i]
			print("Mutation: ", mutation)

			# Count the mutation as occuring once
			frequency_dictionary[mutation] += 1

			# Change the mutation's score in the dictionary by that amount
			mutations_dictionary[mutation] += difference
			print("New score: ", mutations_dictionary[mutation])
			print(hash)
		print("________________________________________________________________________________")
	print("********************************************************************************************************")
	print("********************************************************************************************************")


#print(mutations_dictionary)

sorted_dictionary = sorted(mutations_dictionary.items(), key=operator.itemgetter(1), reverse=True)
#print(sorted_dictionary)

print("Raw Mutation Efficacy")
for i in range(len(sorted_dictionary)):
	print("%d. " % (i+1), sorted_dictionary[i])

for mutation in mutations_dictionary:
	mutations_dictionary[mutation] /= frequency_dictionary[mutation]

sorted_dictionary = sorted(mutations_dictionary.items(), key=operator.itemgetter(1), reverse=True)

print("\nMutation Efficacy Scaled with Frequency")
for i in range(len(sorted_dictionary)):
	print("%d. " % (i+1), sorted_dictionary[i])






