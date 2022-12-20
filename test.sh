#!/bin/sh
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

COUNT_SUCCEEDED=0
COUNT_FAILED=0
COUNT_SKIPPED=0

print_fail()
{
	printf "${RED}$@${NC}\n" 1>&2
}

print_success()
{
	printf "${GREEN}$@${NC}\n"
}

print_skipped()
{
	printf "${YELLOW}$@${NC}\n"
}

runtest_fail()
{
	print_fail "failed"
	COUNT_FAILED=$(($COUNT_FAILED+1))
}

runtest_success()
{
	print_success "ok"
	COUNT_SUCCEEDED=$((COUNT_SUCCEEDED+1))
}

runtest_skipped()
{
	print_skipped "skipped"
	COUNT_SKIPPED=$((COUNT_SKIPPED+1))
}


runtest()
{
	testbin="$1"
	testname="$2"
	test_log_file="$3"

	echo "Running: $testname. Date: $(date)" > "${test_log_file}"

	echo -n "Running $testname... "
	#exit $? to suppress shell message like "./test.sh: line 18: pid Bad system call"
	(./$testbin "$testname" || exit $?) 2>&1 | tee 1>/dev/null -a "${test_log_file}"
	ret=$?
	SUCCESS="no"
	if [ $ret -eq 0 ] ; then
		runtest_success
		SUCCESS="yes"
	elif [ $ret -eq 2 ] ; then
		runtest_skipped
		SUCCESS="skipped"
	else
		runtest_fail
	fi

	echo "Finished: ${testname} (${testbin}). Date: $(date). Success: $SUCCESS" >> "${test_log_file}"
}

GIT_ID=$( git log --pretty="format:%h" -n1 )
TIMESTAMP=$(date +%s)
LOG_OUTPUT_DIR=$1
if [ -z "$LOG_OUTPUT_DIR" ] ; then
LOG_OUTPUT_DIR="./logs/"
fi

LOG_OUTPUT_DIR_PATH="${LOG_OUTPUT_DIR}/exile_test_${GIT_ID}_${TIMESTAMP}"
[ -d "$LOG_OUTPUT_DIR_PATH" ] || mkdir -p "$LOG_OUTPUT_DIR_PATH"

for test in $( ./test --dumptests ) ; do
	testname=$( echo $test )
	runtest test "$testname" "${LOG_OUTPUT_DIR_PATH}/log.${testname}"
done

for test in $( ./testcpp --dumptests ) ; do
	testname=$( echo $test )
	runtest testcpp "$testname" "${LOG_OUTPUT_DIR_PATH}/log.${testname}"
done
echo
echo "Tests finished. Logs in $(realpath ${LOG_OUTPUT_DIR_PATH})"
echo "Succeeded: $COUNT_SUCCEEDED"
echo "Failed: $COUNT_FAILED"
echo "Skipped: $COUNT_SKIPPED"

if [ $COUNT_FAILED -gt 0 ] ; then
	exit 1
fi
exit 0
