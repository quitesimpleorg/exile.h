#!/bin/sh
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

COUNT_SUCCEEDED=0
COUNT_FAILED=0

function print_fail()
{
	echo -e "${RED}$@${NC}" 1>&2
}

function print_success()
{
	echo -e "${GREEN}$@${NC}"
}

function runtest_fail()
{
	print_fail "failed"
	COUNT_FAILED=$(($COUNT_FAILED+1))
}

function runtest_success()
{
	print_success "ok"
	COUNT_SUCCEEDED=$((COUNT_SUCCEEDED+1))
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
			runtest_success
		else
			runtest_fail
		fi
	else
		if [ $ret -eq 0 ] ; then
			runtest_fail
		else
			runtest_success
		fi
	fi
}

for test in $( ./test --dumptests ) ; do
	testname=$( echo $test | cut -d":" -f1 )
	must_exit_zero=$( echo "$test" | cut -d":" -f2 )
	runtest "$testname" $must_exit_zero
done
echo
echo "Tests finished:"
echo "Succeeded: $COUNT_SUCCEEDED"
echo "Failed: $COUNT_FAILED"

if [ $COUNT_FAILED -gt 0 ] ; then
	exit 1
fi
exit 0
