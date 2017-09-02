#! /usr/bin/env python
import random
import os
from shutil import copyfile

filePath = "samples/malwareHashes.txt"
hash_array = []

num_files = input("Enter the number of files to choose: ")

seed = input("Enter the desired seed (or type 'None'): ")

name = input("Enter the desired name for the set (or type 'None'): ")

if seed == None:
	seed = random.randint(1,10000)

if name == None:
	name = "%d_files_%d_seed" % (num_files, seed)

random.seed(seed)
folder = "samples/" + name

if not os.path.isdir(folder):
	os.makedirs(folder)

print "Seed is: %d" % seed
print "Folder path: %s" % folder

with open(filePath,"r") as input:
	for line in input:
		line = line.strip('\n')
		hash_array.append(line)


for i in range(num_files):
	random_num = random.randint(1,len(hash_array)-1) 
	random_hash = hash_array[random_num]
	source = "samples/malware/%s" % random_hash
	destination = folder + "/" + random_hash
	copyfile(source, destination)


print "%d random samples have been chosen and placed in .../PEvadeML/samples/%s" % (num_files, name)



