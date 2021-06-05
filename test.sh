#!/bin/sh
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

function fail()
{
	echo -e "${RED}$@${NC}" 1>&2
	#exit 1
}

function echogreen()
{
	echo -e "${GREEN}$@${NC}"
}

function runtest()
{
	must_exit_zero=$2
	echo -n "Running $1... "
	#exit 1 to suppress shell message like "./test.sh: line 18: pid Bad system call"
	(./test $1 || exit 1) 2> /dev/null
	ret=$?
	if [ $must_exit_zero -eq 1 ] ; then
		if [ $ret -eq 0 ] ; then
			echogreen "ok"
		else
			fail "fail"
		fi
	else
		if [ $ret -eq 0 ] ; then
			fail "fail"
		else
			echogreen "ok"
		fi
	fi
}

for test in $( ./test --dumptests ) ; do
	testname=$( echo $test | cut -d":" -f1 )
	must_exit_zero=$( echo "$test" | cut -d":" -f2 )
	runtest "$testname" $must_exit_zero
done
