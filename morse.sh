#!/bin/bash

#Declaring values in an Array
text=("A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M" "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z" "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "." "," "?" "=" " ");
morse=(".-" "-..." "-.-." "-.." "." "..-." "--." "...." ".." ".---" "-.-" ".-.." "--" "-." "---" ".--." "--.-" ".-." "..." "-" "..-" "...-" ".--" "-..-" "-.--" "--.." "-----" ".----" "..---" "...--" "....-" "....." "-...." "--..." "---.." "----." ".-.-.-" "--..--" "..--.." "-...-" "/");

#funtion for text to morse conversion
to_morse (){
	while IFS= read -n1 -r ch; #reading character by character
	do
		ch=${ch^}
		index=-1;
		for i in ${!text[@]}
		do
			if [[ "${text[$i]}" = "${ch}" ]]
			then 
				index=$i; #finding the index of the character
				break;
			fi
		done
		if [ $index -gt -1 ]
		then 
			echo -n "${morse[$index]} "; #echoing equivalant morse value from morse array
		else
			echo  " ";
		fi
	done < $file
}

#function for morse to text conversion
to_text () {
	blanks=$(awk '{print gsub("[[:blank:]]",""); exit}' < $file)    
	#echo $blanks
	chars=$((blanks+1))
	#echo $chars
	for p in `seq 1 $chars`;
    	do
        	#echo "Test Here $p"
        	char_set=$(cut $file -d ' ' -f $p);
        	index=-1;
        	for i in ${!morse[@]}
        	do
        		if [[ "${morse[$i]}" = "$char_set" ]] #finding index for the char
            		then 
		                index=$i;
                		break;
                	fi
                done
        	if [[ $index -gt -1 ]]
        	then 
           		echo -n "${text[$index]}"; #repace that char by equivalent text character
        	else
            		echo " ";
        	fi
	done
}

#driver code
file=$1;
ext=${file##*.};
if [ $ext == "txt" ]
then
	to_morse;
elif [ $ext == "morse" ]
then
	to_text;
else
	echo  "Error: Please enter a '.txt' or '.morse' file";
fi
