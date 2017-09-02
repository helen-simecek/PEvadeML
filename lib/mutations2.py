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

# NOTE: I didn't write the majority of this file, taken from Hyrum's gym-malware repo 

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

# Custom exception (from EndGame code) to handle if a chosen action (file manipulation) takes too long
class Watchdog(Exception):
	def __init__(self, time=5):
		self.time = time
  
	def __enter__(self):
		signal.signal(signal.SIGALRM, self.handler)
		signal.alarm(self.time)
  
	def __exit__(self, type, value, traceback):
		signal.alarm(0)
	
	def handler(self, signum, frame):
		raise self
  
	def __str__(self):
		return "The code you executed took more than {} to complete".format( self.time )

# Class to perform file manipulations on a given variant 
class MalwareManipulator(object):
	def __init__(self, bytez): 
		self.bytez = bytez
		self.min_append_log2 = 5
		self.max_append_log2 = 8
		logger = logging.getLogger('gp.mutator')

	def __random_length(self): 
		return 2**random.randint( self.min_append_log2, self.max_append_log2 ) 

	# Method to rebuild the binary and return as bytes
	def __binary_to_bytez(self, binary, dos_stub=False, imports=False, overlay=False, relocations=False, resources=False, tls=False):
		# write the file back as bytez
		builder = lief.PE.Builder(binary)
		builder.build_dos_stub(dos_stub) # rebuild DOS stub
		builder.build_imports(imports) # rebuild IAT in another section
		builder.patch_imports(imports) # patch original import table with trampolines to new import table
		builder.build_overlay(overlay) # rebuild overlay
		builder.build_relocations(relocations) # rebuild relocation table in another section
		builder.build_resources(resources) # rebuild resources in another section
		builder.build_tls(tls) # rebuilt TLS object in another section

		builder.build() # perform the build process		
		return array.array('B', builder.get_build()).tobytes() # verison as of 22/7/17

	# Mutation that overlays random bytes from a given range
	def overlay_append(self,seed=None): 
		#random.seed(seed)
		L = self.__random_length()
		# choose the upper bound for a uniform distribution in [0,upper]
		upper = random.randrange(256)
		# upper chooses the upper bound on uniform distribution:
		# upper=0 would append with all 0s
		# upper=126 would append with "printable ascii"
		# upper=255 would append with any character
		return self.bytez + bytes([random.randint(0, upper) for _ in range(L)])

	# Mutation that adds extra imports to the imports list
	def imports_append(self,seed=None): 
		# add (unused) imports
		binary = lief.PE.parse(self.bytez)
		
		# draw a library at random (must draw from the sorted list for repeatable results)
		randomNum = random.randint(0,len(COMMON_IMPORTS_DETERMINISTIC)-1)
		libname = COMMON_IMPORTS_DETERMINISTIC[randomNum][0]

		funcname = random.choice(COMMON_IMPORTS_DETERMINISTIC[randomNum][1])
		lowerlibname = libname.lower()
		# find this lib in the imports, if it exists
		lib = None
		for im in binary.imports:
			if im.name.lower() == lowerlibname:
				lib = im
				break
		if lib is None:
			# add a new library
			lib = binary.add_library(libname)
		# get current names
		names = set([e.name for e in lib.entries])
		if not funcname in names:
			lib.add_entry(funcname)

		self.bytez = self.__binary_to_bytez(binary,imports=True)

		return self.bytez
	
	# Mutation that renames a section
	def section_rename(self,seed=None): 
		binary = lief.PE.parse(self.bytez)
		targeted_section = random.choice(binary.sections)
		targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7] # current version of lief not allowing 8 chars?
		self.bytez = self.__binary_to_bytez(binary)

		return self.bytez

	# Mutation that adds a section 
	def section_add(self,seed=None):    
		binary = lief.PE.parse(self.bytez)
		new_section = lief.PE.Section(
			"".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))

		# fill with random content
		upper = random.randrange(256)
		L = self.__random_length()
		new_section.content = [random.randint(0, upper) for _ in range(L)]

		new_section.virtual_address = max(
			[s.virtual_address + s.size for s in binary.sections])
		# add a new empty section

		binary.add_section(new_section,
						   random.choice([
							   lief.PE.SECTION_TYPES.BSS,
							   lief.PE.SECTION_TYPES.DATA,
							   lief.PE.SECTION_TYPES.EXPORT,
							   lief.PE.SECTION_TYPES.IDATA,
							   lief.PE.SECTION_TYPES.RELOCATION,
							   lief.PE.SECTION_TYPES.RESOURCE,
							   lief.PE.SECTION_TYPES.TEXT,
							   lief.PE.SECTION_TYPES.TLS_,
							   lief.PE.SECTION_TYPES.UNKNOWN,
						   ]))

		self.bytez = self.__binary_to_bytez(binary)
		return self.bytez

	# Mutation that appends to the end of a section (does not append an entire new section)
	def section_append(self,seed=None): 
		# append to a section (changes size and entropy)
		binary = lief.PE.parse(self.bytez)
		targeted_section = random.choice(binary.sections)
		L = self.__random_length()
		available_size = targeted_section.size - len(targeted_section.content)
		if L > available_size:
			L = available_size

		upper = random.randrange(256)
		targeted_section.content = targeted_section.content + \
			[random.randint(0, upper) for _ in range(L)]

		self.bytez = self.__binary_to_bytez(binary)
		return self.bytez

	# Mutation that creates a new entry point in the file
	def create_new_entry(self,seed=None):   
		# create a new section with jump to old entry point, and change entry point
		# DRAFT: this may have a few technical issues with it (not accounting for relocations), but is a proof of concept for functionality

		binary = lief.PE.parse(self.bytez)

		# get entry point
		entry_point = binary.optional_header.addressof_entrypoint

		# get name of section
		entryname = binary.section_from_rva(entry_point).name

		# create a new section
		new_section = lief.PE.Section(entryname + "".join(chr(random.randrange(
			ord('.'), ord('z'))) for _ in range(3)))  # e.g., ".text" + 3 random characters
		# push [old_entry_point]; ret
		new_section.content = [
			0x68] + list(struct.pack("<I", entry_point + 0x10000)) + [0xc3]
		new_section.virtual_address = max(
			[s.virtual_address + s.size for s in binary.sections])
		# TO DO: account for base relocation (this is just a proof of concepts)

		# add new section
		binary.add_section(new_section, lief.PE.SECTION_TYPES.TEXT)

		# redirect entry point
		binary.optional_header.addressof_entrypoint = new_section.virtual_address

		self.bytez = self.__binary_to_bytez(binary)
		return self.bytez

	# Mutation that performs a upx packing operation on the file (compresses)
	def upx_pack(self,seed=None):   
		# tested with UPX 3.91	
		tmpfilename = os.path.join(
			tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

		# dump bytez to a temporary file
		with open(tmpfilename, 'wb') as outfile:
			outfile.write(self.bytez)

		options = ['--force', '--overlay=copy']
		compression_level = random.randint(1, 9)
		options += ['-{}'.format(compression_level)]
		#--exact						# Oh, these comments are to explain what the options do?
		#compression levels -1 to -9
		#--overlay=copy [default]

		#optional things:
		#--compress-exports=0/1
		#--compress-icons=0/1/2/3
		#--compress-resources=0/1
		#--strip-relocs=0/1
		options += ['--compress-exports={}'.format(random.randint(0, 1))]
		options += ['--compress-icons={}'.format(random.randint(0, 3))]
		options += ['--compress-resources={}'.format(random.randint(0, 1))]
		options += ['--strip-relocs={}'.format(random.randint(0, 1))]

		with open(os.devnull, 'w') as DEVNULL:
			retcode = subprocess.call(
				['upx'] + options + [tmpfilename, '-o', tmpfilename + '_packed'], stdout=DEVNULL, stderr=DEVNULL)

		os.unlink(tmpfilename)

		if retcode == 0:  # successfully packed

			with open(tmpfilename + '_packed', 'rb') as infile:
				self.bytez = infile.read()

			os.unlink(tmpfilename + '_packed')

		return self.bytez

	# Mutation that performs a upx unpack operation on the file (decompresses)
	def upx_unpack(self,seed=None):     
		# dump bytez to a temporary file
		tmpfilename = os.path.join(
			tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

		with open(tmpfilename, 'wb') as outfile:
			outfile.write(self.bytez)

		with open(os.devnull, 'w') as DEVNULL:
			retcode = subprocess.call(
				['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], stdout=DEVNULL, stderr=DEVNULL)

		os.unlink(tmpfilename)

		if retcode == 0:  # sucessfully unpacked
			with open(tmpfilename + '_unpacked', 'rb') as result:
				self.bytez = result.read()

			os.unlink(tmpfilename + '_unpacked')

		return self.bytez

	# Mutation that removes the signature from a file (if found)
	def remove_signature(self, seed=None):
		binary = lief.PE.parse(self.bytez)

		if binary.has_signature:
			for i, e in enumerate(binary.data_directories):
				if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
					break
			if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
				# remove signature from certificate table
				e.rva = 0
				e.size = 0
				self.bytez = self.__binary_to_bytez(binary)
				return self.bytez
		# if no signature found, self.bytez is unmodified
		return self.bytez

	# Mutation that removes debugging information (if found)
	def remove_debug(self, seed=None):
		#random.seed(seed)
		binary = lief.PE.parse(self.bytez)

		if binary.has_debug:
			for i, e in enumerate(binary.data_directories):
				if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
					break
			if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
				# remove debugging info from certificate table
				e.rva = 0
				e.size = 0
				self.bytez = self.__binary_to_bytez(binary)
				return self.bytez
		# if no debugging info found, self.bytez is unmodified
		return self.bytez

	# Mutation that modifies the checkum in the optional header section    
	def break_optional_header_checksum(self, seed=None):
		binary = lief.PE.parse(self.bytez)
		binary.optional_header.checksum = 0
		self.bytez = self.__binary_to_bytez(binary)
		return self.bytez
#########################################################################################################################

# Identity function that just returns itself
def identity(bytez,seed=None):  
	return bytez

# explicitly list the mutations so that they can be used externally (although they're never used externally in this case...)
# Not used now, but could be used if functions are moved
ACTION_TABLE = {
	'do_nothing': identity,
	'overlay_append': 'overlay_append',
	'imports_append': 'imports_append',
	'section_rename': 'section_rename',
	'section_add': 'section_add',
	'section_append': 'section_append',
	'create_new_entry': 'create_new_entry',
	'remove_signature': 'remove_signature',
	'remove_debug': 'remove_debug',
	'upx_pack': 'upx_pack',
	'upx_unpack': 'upx_unpack',
	'break_optional_header_checksum': 'break_optional_header_checksum',
	#   'modify_exports' : modify_exports,
}

# Function to manipulate the file in a way that SUPPOSEDLY doesn't break the malicious behavior of the file
def modify_without_breaking(bytez, vid, action):
	logger = logging.getLogger('gp.modify')
	logger.info("Variant %d: Performed %s" % (vid,action))

	#malMan = MalwareManipulator(bytez)
	action = MalwareManipulator(bytez).__getattribute__(action)
	try:
		bytez = action()
	except (KeyboardInterrupt, SystemExit):
		raise
	except (RuntimeError,UnicodeDecodeError,TypeError, lief.not_found):
		pass # some exceptions that have yet to be handled by public release of LIEF
	except:
		raise
		
	return bytez


# Method that will perform a mutation
# Note - this could be combined with modify_without_breaking, moved back into the GP class, or something else 
def mutate(variant, vid):
	
	# Array of possible mutations to be performed
	actions_array = ['overlay_append','imports_append','section_rename','section_add','section_append','create_new_entry','upx_pack','upx_unpack', 'remove_signature', 'break_optional_header_checksum']
	
	# Choose a random number, choose that element in the actions array as the action, append that operation to the trace
	random_num = random.randint(0,len(actions_array)-1)
	action = actions_array[random_num]
	variant.trace.append(action)

	# Perform that operation
	bytez = modify_without_breaking(variant.bytez, vid, action)
	
	# Update the variant with the new bytestring
	variant.bytez = bytez



