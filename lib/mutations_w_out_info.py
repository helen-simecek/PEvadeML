import lief
import json
import os
import sys
import array 
import struct # byte manipulations
import random
import tempfile
import subprocess
import logging
import functools
import signal
import pdb
import traceback
import hashlib

# FILE WITH MOST CODE REDACTED (ENDGAME'S, NOT OURS)

module_path = os.path.split( os.path.abspath( sys.modules[__name__].__file__ ) )[0]

# Two documents with common PE information to be used in file manipulations/mutations
COMMON_SECTION_NAMES = open( os.path.join(module_path,'section_names.txt'), 'r').read().rstrip().split('\n')
COMMON_IMPORTS = json.load( open( os.path.join( module_path, 'small_dll_imports.json'), 'r') )

# Array to hold the imports after they've been sorted (dictionaries in python are not deterministic otherwise)
COMMON_IMPORTS_DETERMINISTIC = []

# Column 0 is the key (library name), column 1 is the value (function name) 
for key in COMMON_IMPORTS:
	row = [key, list(COMMON_IMPORTS[key]).sort()]
	COMMON_IMPORTS_DETERMINISTIC.append(row)


# INSERT: Class to perform file manipulations on a given variant 

#########################################################################################################################

# List all possible mutations (for external use)
ACTION_TABLE = {
	# INSERT
}

# Function to manipulate the file in a way that SUPPOSEDLY doesn't break the malicious behavior of the file
def modify_without_breaking(bytez, vid, action):
	logger = logging.getLogger('gp.modify')
	logger.info("Variant %d: Performed %s" % (vid,action))

	# INSERT: Perform the action
		
	return bytez


# Method that will perform a mutation
# Note - this could be combined with modify_without_breaking, moved back into the GP class, or something else 
def mutate(variant, vid):
	
	# Array of possible mutations to be performed (INSERT ACTIONS)
	actions_array = []
	
	# Choose a random number, choose that element in the actions array as the action, append that operation to the trace
	random_num = random.randint(0,len(actions_array)-1)
	action = actions_array[random_num]
	variant.trace.append(action)

	# Perform that operation
	bytez = modify_without_breaking(variant.bytez, vid, action)
	
	# Update the variant with the new bytestring
	variant.bytez = bytez



