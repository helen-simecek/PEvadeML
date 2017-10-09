***********
PEvadeML
***********

A framework for evading machine learning based Windows PE malware classifiers. Modified from the original EvadeML (https://evademl.org/).

# Set-up

(TO-DO)

# Usage

(TO-DO)

File Information: 

batch.py		Python script for running gp code on multiple samples at once
count_files.sh		Bash script to count the number of files in directories (sloppy way to count the number of evasive variants found)
diff_vars.sh		Bash script to print the differences between two different variants (binary -> LIEF binary -> text output -> UNIX diff function)
file_picker.py		Python script for randomly selecting a subset of samples to be used instead of the entire samples directory
mutation_efficacy.py	Python script for measuring the average effect that each mutation had on the variants tested
print_variant.py	Python script used to print out a binary file in LIEF binary format (used in the diff_vars.sh shell script)
project.conf		Configuration file that currently only takes in information to be used in the batch.py script
gp.py			Main program
