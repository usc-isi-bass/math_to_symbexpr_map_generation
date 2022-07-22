# iterate over list of line numbers

# IO handling
#in="/dev/stdin"
out="/dev/stdout"
# user should pass line numbers file as a positional arg

# get nth line and print to output file
cat $1 | while read line
do
    #echo $line
    sed -i "${line}d" $2 
done
