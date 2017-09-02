import lief
import sys

#file_path = input("Enter the file path to the variant: ")

if len(sys.argv) < 2:
	print("python3 print_variant.py <path/to/variant>")
	sys.exit(1)

file_path = sys.argv[1]

binary = lief.PE.parse(file_path)

print(binary)

