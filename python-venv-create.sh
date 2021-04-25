#!/usr/bin/env bash

set -e -u

_required_major_version=3
_required_minor_version=8

HOST=`uname -n`
ME=`basename $0`
OS=`uname`
# tmpfile=`mktemp -t $ME.XXXXX`

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
    errecho "usage:${ME} [ -hnx ]"
    exit 1
}

N=" "
####################
### Process command line arguments
while getopts hnx opt
do
  case $opt in
    # Look for signs for help...
    h) # help
      cat <<EOF
-h You're soaking in it.
-n noop / dryrun
-x set -x
EOF
      exit 1
      ;;
    n) N=echo;;
    x) set -x;;
    *) usage ;;
  esac
done

# This gets rid off all the command line flags and their args, so that
# only the file or dir. name(s) remain.
shift `expr $OPTIND - 1`

####################

# rm $tmpfile


if [ $# -ne 2 ] ; then
	die 11 "Please supply two arguments: the python interpreter AND the destination directory where the venv will be created"
fi
_python="${1}"
_venv_dir="${2}"

_python_release=`"${_python}" --version | sed 's/^Python //'`
_python_major_version=`echo $_python_release | awk -F. '{print $1}'`
_python_minor_version=`echo $_python_release | awk -F. '{print $2}'`
_python_series="${_python_major_version}.${_python_minor_version}"

_old_version_mess="The RIPE Atlas packages require version ${_required_major_version}.${_required_minor_version} or later for proper SSL support."
if [ "${_python_major_version}" -lt $_required_major_version ] ; then
	die 12 "${_old_version_mess}"
elif [ $_python_minor_version -lt $_required_minor_version ] ; then
	die 13 "${_old_version_mess}"
fi

_pip3="pip-${_python_series}"

"${_python}" -m venv "${_venv_dir}"
#env
source "${_venv_dir}/bin/activate"
#echo "------"
#env
type pip
set -x
pip install --upgrade pip
pip install -r requirements.txt
