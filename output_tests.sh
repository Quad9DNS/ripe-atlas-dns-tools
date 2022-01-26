#!/bin/sh

#
# Run some tests of the ra-dns-check.py script to see if it's working as expected

set -e -u

HOST=`uname -n`
ME=`basename $0`
OS=`uname`
tmpfile1=`mktemp -t $ME.XXXXX`
tmpfile2=`mktemp -t $ME.XXXXX`

# Provide for comparing output of two different versions of the script
ra1=./ra-dns-check.py
ra2="${ra1}"
create_benchmark_output=false
TEST_DATA_DIR=./Test-Data
test_AB_source_file_1="${TEST_DATA_DIR}/RIPE-Atlas-measurement-29083406.json"
test_AB_source_file_2="${TEST_DATA_DIR}/RIPE-Atlas-measurement-29096558.json"
benchmark_AB_file_prefix="${TEST_DATA_DIR}/benchmark-test-output-AB"
#
# test_date_diff_v4_source_file="${TEST_DATA_DIR}/RIPE-Atlas-measurement-12016229.json"
test_date_diff_v4_mesid="12016229"
benchmark_date_diff_v4_file_prefix="${TEST_DATA_DIR}/benchmark-test-output-date_diff_v4"
#
# test_date_diff_v6_source_file="${TEST_DATA_DIR}/RIPE-Atlas-measurement-12016241.json"
test_date_diff_v6_mesid="12016241"
benchmark_date_diff_v6_file_prefix="${TEST_DATA_DIR}/benchmark-test-output-date_diff_v6"

test_opts='all_probes color no_color emphasis_chars no_header latency_diff_threshold
 do_not_list_probes list_slow_probes_only slow_threshold print_summary_stats'
# Echo our args to standard error.
errecho()
{
  echo "$*" >&2
}

die() {
  errcode=$1
  shift
  errecho "$*"
  exit $errcode
}

# The infamous usage function.
usage()
{
    errecho "usage:${ME} [ -hnxB ] [-1 path-to-scriptv1] [-2 path-to-scriptv2] [ -t /path/to/test/data/dir/] "
    exit 1
}

N=" "
date_time_only=false
ip_v4_only=false
ip_v6_only=false
####################
### Process command line arguments
while getopts hnxBD1:2:t:46 opt
do
  case $opt in
    # Look for signs for help...
    h) # help
      cat <<EOF
-h You're soaking in it.
-n noop / dryrun
-x set -x
-B create Benchmark output (overwrites existing files)
-D date_time_only
-1 path to the script to run for test1
-2 path to the script to run for test2
-4 ip_v4_only
-6 ip_v6_only
-t /path/to/test/data/dir/
EOF
      exit 1
      ;;
    n) N=echo;;
    x) set -x;;
		1) ra1=$OPTARG;;
		2) ra2=$OPTARG;;
		t) TEST_DATA_DIR="${OPTARG}";;
		B) create_benchmark_output=true;;
		D) date_time_only=true;;
		4) ip_v4_only=true;;
		6) ip_v6_only=true;;
    *) usage ;;
  esac
done

# This gets rid off all the command line flags and their args, so that
# only the file or dir. name(s) remain.
shift `expr $OPTIND - 1`


####################

if [ "${ra1}" = "${ra2}" ] ; then
	one_script=true
else
	one_script=false
fi

# compare output of 2-file input
if [ $date_time_only = "false" ] && [ $ip_v6_only = "false" ] ; then
	for opt in $test_opts
	do
		opt_arg=''
		case $opt in
			latency_diff_threshold) opt_arg=10;;
			slow_threshold) opt_arg=50 ;;
		esac
		benchmark_AB_file="${benchmark_AB_file_prefix}-${opt}"
		./ra-dns-check.py --config_file ./default_config_file \
											--${opt} ${opt_arg} \
											"${test_AB_source_file_1}" \
											"${test_AB_source_file_2}" \
											> $tmpfile1 2>&1
		if [ $create_benchmark_output = 'true' ]; then
			echo "Updating ${benchmark_AB_file}"
			mv "${tmpfile1}" "${benchmark_AB_file}"
		else
			echo "Diffing vs. ${benchmark_AB_file}"
			set +e
			diff "${benchmark_AB_file}" "${tmpfile1}"
			case $? in
				1)
					errecho "Unexpected differences in output exist; you can find suspect output in tempfiles:"
					errecho " ${tmpfile1}"
					if [ $one_script = 'false' ] ; then
						errecho " ${tmpfile2}"
					fi
					errecho "Compare with what's in ${TEST_DATA_DIR}"
					errecho "Exiting."
					exit 1
					;;
			esac
			set -e
		fi
	done
fi

# compare output of one IPv4 inputfile with a date range
if [ $ip_v6_only = "false" ] ; then
	for opt in $test_opts
	do
		opt_arg=''
		case $opt in
			latency_diff_threshold) opt_arg=10;;
			slow_threshold) opt_arg=50 ;;
		esac

		benchmark_date_diff_v4_file="${benchmark_date_diff_v4_file_prefix}-${opt}"
		./ra-dns-check.py --config_file ./default_config_file \
											--${opt} ${opt_arg} \
											--datetime1 20210515.09:45 \
											--datetime2 20210522.09:45 \
											"${test_date_diff_v4_mesid}" \
											> $tmpfile1 2>&1
		if [ $create_benchmark_output = 'true' ]; then
			echo "Updating ${benchmark_date_diff_v4_file}"
			mv "${tmpfile1}" "${benchmark_date_diff_v4_file}"
		else
			echo "Diffing vs. ${benchmark_date_diff_v4_file}"
			set +e
			diff "${benchmark_date_diff_v4_file}" "${tmpfile1}"
			case $? in
				1)
					errecho "Unexpected differences in output exist; you can find suspect output in tempfiles:"
					errecho " ${tmpfile1}"
					if [ $one_script = 'false' ] ; then
						errecho " ${tmpfile2}"
					fi
					errecho "Compare with what's in ${TEST_DATA_DIR}"
					errecho "Exiting."
					exit 1
					;;
			esac
			set -e
		fi
	done
fi


# compare output of one IPv6 inputfile with a date range
if [ $ip_v4_only = "false" ] ; then
	for opt in $test_opts
	do
		opt_arg=''
		case $opt in
			latency_diff_threshold) opt_arg=10;;
			slow_threshold) opt_arg=50 ;;
		esac

		benchmark_date_diff_v6_file="${benchmark_date_diff_v6_file_prefix}-${opt}"
		./ra-dns-check.py --config_file ./default_config_file \
											--${opt} ${opt_arg} \
											--datetime1 20210515.09:45 \
											--datetime2 20210522.09:45 \
											"${test_date_diff_v6_mesid}" \
											> $tmpfile1 2>&1
		if [ $create_benchmark_output = 'true' ]; then
			echo "Updating ${benchmark_date_diff_v6_file}"
			mv "${tmpfile1}" "${benchmark_date_diff_v6_file}"
		else
			echo "Diffing vs. ${benchmark_date_diff_v6_file}"
			set +e
			diff "${benchmark_date_diff_v6_file}" "${tmpfile1}"
			case $? in
				1)
					errecho "Unexpected differences in output exist; you can find suspect output in tempfiles:"
					errecho " ${tmpfile1}"
					if [ $one_script = 'false' ] ; then
						errecho " ${tmpfile2}"
					fi
					errecho "Compare with what's in ${TEST_DATA_DIR}"
					errecho "Exiting."
					exit 1
					;;
			esac
			set -e
		fi
	done
fi


if [ $create_benchmark_output = 'true' ]; then
	exit 0
else
	$N rm -f $tmpfile1
	$N rm -f $tmpfile2
fi

trap 'errexit' ERR


