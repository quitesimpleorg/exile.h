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
	testname="$1"
	test_log_file="$2"

	echo "Running: $testname. Date: $(date)" > "${test_log_file}"

	echo -n "Running $1... "
	#exit $? to suppress shell message like "./test.sh: line 18: pid Bad system call"
	(./test $1 || exit $?) &>> "${test_log_file}"
	ret=$?
	SUCCESS="no"
	if [ $ret -eq 0 ] ; then
		runtest_success
		SUCCESS="yes"
	else
		runtest_fail
	fi

	echo "Finished: ${testname}. Date: $(date). Success: $SUCCESS" >> "${test_log_file}"
}

GIT_ID=$( git log --pretty="format:%h" -n1 )
TIMESTAMP=$(date +%s)
LOG_OUTPUT_DIR=$1
if [ -z "$LOG_OUTPUT_DIR" ] ; then
LOG_OUTPUT_DIR="./logs/"
fi

LOG_OUTPUT_DIR_PATH="${LOG_OUTPUT_DIR}/qssb_test_${GIT_ID}_${TIMESTAMP}"
[ -d "$LOG_OUTPUT_DIR_PATH" ] || mkdir -p "$LOG_OUTPUT_DIR_PATH"

for test in $( ./test --dumptests ) ; do
	testname=$( echo $test )
	runtest "$testname" "${LOG_OUTPUT_DIR_PATH}/log.${testname}"
done
echo
echo "Tests finished. Logs in $(realpath ${LOG_OUTPUT_DIR_PATH})"
echo "Succeeded: $COUNT_SUCCEEDED"
echo "Failed: $COUNT_FAILED"


if [ $COUNT_FAILED -gt 0 ] ; then
	exit 1
fi
exit 0
