#/usr/bin/env yash

set -ex --pipe-fail

# Initialize array
A=()
array -i A -1 a
array -i A -1 b
array -i A -1 c

# or
A=(a b c)

# Append to array
array -i A -1 foo
echo $A

# Delete from array
array -d A -1
echo $A

# Index in array
echo ${A[1]}
echo ${A[2]}
i=3
echo ${A[i]}

# Iterate through array
for x in ${A[@]}
do
	echo $x
done

# Pass array to function as length items...
an_arr_fn() {
  len=$1
  shift

  remake=()

  i=1
  while [ $i -le $len ]
  do
    x=$1
    array -i remake -1 $x

    i=$((i + 1))
    shift
  done

  echo $remake
}

an_arr_fn ${A[#]} ${A[@]}
