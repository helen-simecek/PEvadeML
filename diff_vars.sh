#!/bin/bash
# To use: ./diff_vars.sh <path/to/file1> <path/to/file2> 

# Two files to compare (taken from cmdline params)
FILE1=$1
FILE2=$2

# Run the print variant python script for each file - loads file path to variant and prints the binary - save to text files
python3 print_variant.py $FILE1 > file1.txt 
python3 print_variant.py $FILE2 > file2.txt

# Compare the two new text files with diff (prints to console)
diff file1.txt file2.txt

# Remove the two text files created during the process
rm file1.txt
rm file2.txt


