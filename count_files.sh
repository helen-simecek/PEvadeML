#!/bin/bash

FILES=/PATH/TO/RESULTS/FILES
EVADED=0
NOT_EVADED=0
FAILED=0

# Not the best system, but counts the number of files in each directory and concludes whether
# or not that sample found an evasive variant based on that (would need to change the compareTo
# numbers based on what the results files are storing
for fileName in $FILES; do
	#echo $fileName
	cd $fileName
	#pwd
	COUNT="$(ls | wc -l)"
	#echo $COUNT
	if [[ ( "$COUNT" = "1" ) || ( "$COUNT" = "2" ) ]]
	then
		FAILED=$((FAILED+1))
	#fi
	elif [ "$COUNT" = "5" ]
	then
		NOT_EVADED=$((NOT_EVADED+1))
	elif [ "$COUNT" = "6" ]
	then
		EVADED=$((EVADED+1))
	else
		echo "ERROR: Unaccounted for number of files!"
		echo $fileName
	fi
	#echo $COUNT
	cd ".."
done

echo "$EVADED files found evasive variants"
echo "$NOT_EVADED files were not able to find evasive variants"
echo "$FAILED files failed for some reason"

#Cmd= "ls | wc -l"
#count="$(ls | wc -l)"
#echo $count
