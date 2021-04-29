#!/usr/bin/env python3
#
# ra-dns-check.py, v2.2
#
# Parse, summarize, sort, and display RIPE Atlast measurement results for DNS queries

# Please see the file LICENSE for the license.

import argparse
# need this to more safely parse config file
import ast
import configparser
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime
# to decompress RIPE Atlas probe data file
import bz2
# needed to fetch the probe properties file from RIPE
import urllib.request
# These RIPE puthon modules are usually installed with pip:
from ripe.atlas.cousteau import AtlasLatestRequest
from ripe.atlas.cousteau import AtlasResultsRequest
from ripe.atlas.cousteau import Probe
from ripe.atlas.sagan import DnsResult
from ripe.atlas.cousteau import Measurement
# for debugging
from pprint import pprint

###################
#
# Configurable settings
#
my_config_file = os.environ['HOME'] + '/.ra-dns-check.conf'

# Options can be set or changed on the command line of via config file.
#
# Help text is defined as strings here so it can be consistently presented
# in both the config file and --help (usage).
#
# These are dictionaries we'll iterate over to generate the config text,
# including a Big Blurb o' Help.  There are three different dictionaries
# for the different data types (string, integer, boolean) because by
# default, ConfigParser reads everything in as a string, but there are ways to read specific sections or values as int or bool.


options_setup_dict_string = {
    'datetime1': {
        'default': None,
        'help': 'date-time to start 10-minute period for FIRST set of results (UTC).\n; Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")'},
    'datetime2': {
        'default': None,
        'help': 'date-time to start 10-minute period for SECOND set of results (UTC).\n;  Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")'},
    'split_char': {
        'default': '.',
        'help': 'character (delimiter) to split the string on (can occur in the string more than once.'},

}
options_setup_dict_boolean = {
    'all_probes': {
        'default': False,
        'help': 'show information for probes presnt in *either* result sets, not just those present in *both* sets'},
    'color': {
        'default': True,
        'help': 'colorize output'},
    'no_color': {
        'default': False,
        'help': 'do NOT colorized output (AKA "colourised output")'},
    'emphasis_chars': {
        'default': False,
        'help': 'add a trailing char (! or *) to abberant sites and response times'},
    'no_header': {
        'default': False,
        'help': 'Do NOT show the header above the probe list'},
    'do_not_list_probes': {
        'default': False,
        'help': 'do NOT list the results for each probe'},
    'list_slow_probes_only': {
        'default': False,
        'help': 'in per-probe list,show ONLY the probes reporting response times'},
    'print_summary_stats': {
        'default': False,
        'help': 'show summary stats'}
}
options_setup_dict_integer = {
    'dns_response_item_occurence_to_return': {
        'default': 1,
        'help': 'Which item to return from the split-list. First element is 0.'},
    'latency_diff_threshold': {
        'default': 5,
        'help': 'the amount of time difference (ms) that is significant when comparing latencies bewtween tests'},
    'slow_threshold': {
        'default': 50,
        'help': 'Response times (ms) larger thatn this trigger color highlighting.'},
    'raw_probe_properties_file_max_age': {
        'default': 86400,
        'help': 'The max age of the RIPE Atlas probe info file. (older than this and we download a new one)'}
}
#
# There are some defaults defined in the "sample_config" string below, but
# you should edit them in the config file instead of bellow.
# (If the config file does not exist, this script creates it from this string.)
#
# Options specified in the command line can then also be overridden by what's specified on the command line.
#
sample_config = """;
; Config file for ra-dns-check.py
;
; This file is automatically created if it does not exist.
; After its initial creation, the script won't change it, but you can!
; (If you ever want to reset everything to the script defaults,
;  you can rename or delete this file and the script will create a new one.)
;
; Some important notes on this file's syntax :
;
; 1) This file is read by the ConfigParser python module, and therefore
;    (perhaps surprisingly) it expects Windoze INI syntax *NOT* python
;    syntax. So:
;    * do NOT enclose strings within quotes or double quotes
;      (they will be passed along with the string and break things)
;    * protect/escape any '%' character with another '%'
;    *  either ':' or '=' can be used to separate a config variable (key) and its value.
;    * spaces are allowed *within* (as part of) a value or key!
;      (So be careful of leading spaces before key names.
;       E.g ' probe_properties_to_report = ...' will break!)
;
; 2) Do not remove or change the section names:
;    [STRING], [BOOLEAN], [INTEGER]
;    (use of python's ConfigParser module depend upon it.)
;
; 3) Keep the key-value pairs in the approriate section for their type:
;    string, boolean, or integer.

;;;;;;;;;;;;;;;;;;;;
[STRING]
;
; Wikipedia says 2010 was when RIPE Atlas was established, so we use that
; as a starting point for when it might contain some data.
oldest_atlas_result_datetime = 2010 01 01 00:00:00
;
; There are a couple of files used to locally cache probe data, the first comes directly from RIPE:
ripe_atlas_probe_properties_raw_file = """ + os.environ['HOME'] + '/.RIPE_atlas_all_probe_properties.bz2' + """
;
; the second cache file we generate, based upon probe info we request (one at a time) from the RIPE Atlas API.
ripe_atlas_probe_properties_json_cache_file = """ + os.environ['HOME'] + '/.RIPE_atlas_probe_properties_cache_file.json' + """
;
; where to fetch the RA probe properties file
ripe_atlas_current_probe_properties_url = https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest
;
; The ordered list of properties to display in the (default) detailed listing per probe.
probe_properties_to_report = ['probe_id', 'asn', 'country_code',
                               'ip_address', 'rt_a', 'rt_b', 'rt_diff', 'dns_response']
"""
# List of the config paramaters from the initial text above ^.
# (It will be appended to using subsequent for loops to read through options dictionaries.)
expected_config_items =['oldest_atlas_result_datetime',
                        'ripe_atlas_probe_properties_raw_file',
                        'ripe_atlas_probe_properties_json_cache_file',
                        'ripe_atlas_current_probe_properties_url',
                        'probe_properties_to_report']
# Iterate over the items in the options_setup_dict (defined above)
# These are the options that can be specified in the config file OR on the command line.
for k in options_setup_dict_string.keys():
    sample_config += (';\n')
    sample_config += ('; ' + options_setup_dict_string[k]['help'] + '\n')
    sample_config += (k + ' = ' + str(options_setup_dict_string[k]['default']) + '\n')
    expected_config_items.append(k)
#
sample_config += "\n;;;;;;;;;;;;;;;;;;;;\n[BOOLEAN]\n"
for k in options_setup_dict_boolean.keys():
    sample_config += (';\n')
    sample_config += ('; ' + options_setup_dict_boolean[k]['help'] + '\n')
    sample_config += (k + ' = ' + str(options_setup_dict_boolean[k]['default']) + '\n')
    expected_config_items.append(k)
#
sample_config += "\n;;;;;;;;;;;;;;;;;;;;\n[INTEGER]\n"
for k in options_setup_dict_integer.keys():
    sample_config += (';\n')
    sample_config += ('; ' + options_setup_dict_integer[k]['help'] + '\n')
    sample_config += (k + ' = ' + str(options_setup_dict_integer[k]['default']) + '\n')
    expected_config_items.append(k)

####################
#
# Config file parse
#
raw_config = configparser.ConfigParser()
try:
    if os.stat(my_config_file):
        if os.access(my_config_file, os.R_OK):
            ### sys.stderr.write('Found config file at %s; reading it now...\n' % my_config_file)
            raw_config.read(my_config_file)
        else:
            sys.stderr.write('Config file exists at %s, but is not readable.\n' % my_config_file)
except FileNotFoundError:
    ### sys.stderr.write('Config file does not exist at %s; creating new one...\n' % my_config_file)
    raw_config.read_string(sample_config)
    with open(my_config_file, 'w') as cf:
        cf.write(sample_config)

### print(raw_config.sections())
raw_config_string = raw_config['STRING']
raw_config_boolean = raw_config['BOOLEAN']
raw_config_integer = raw_config['INTEGER']
#
# Loop through what's in config and see if each variable is in the
# (following) list of expected config variables, so we can catch any
# unexpected ("illegal") parameters in the config file, rather than let a
# typo or some bit of random (non-comment) text in the config file go
# unnoticed.
config = {}
for item in raw_config_string:
    ### print(item)
    if item not in expected_config_items:
        sys.stderr.write('Unknown parameter in config file: %s\n' % item)
        exit(1)
    else:
        config[item] = raw_config_string[item]
        ###print(item + config[item])
for item in raw_config_boolean:
    if item not in expected_config_items:
        sys.stderr.write('Unknown parameter in config file: %s\n' % item)
        exit(1)
    else:
        config[item] = raw_config_boolean.getboolean(item)
        ###print(item + str(config[item]))
for item in raw_config_integer:
    ### print(item)
    if item not in expected_config_items:
        sys.stderr.write('Unknown parameter in config file: %s\n' % item)
        exit(1)
    else:
        config[item] = raw_config_integer.getint(item)
        ###print(item + str(config[item]))
# What we get from configparser is a string, so we need to convert it to a list.
# (ast.literal_eval() is safer than plain eval())
probe_properties_to_report = ast.literal_eval(config['probe_properties_to_report'])

#
#
####################
#
# Argument processing and usage info (argparse lib automatically provides -h)
parser = argparse.ArgumentParser(description='Display statistics from RIPE Atlas DNS probes. Data can be from local files or this script will query RIPE Atlas for user-supplied Measurement IDs', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''Examples:
# Compare the results from two local files, "./foo" and "./bar" :
%(prog)s ./foo ./bar

# Compare the results from two items, "12345678" and "87654321"
# (if the items cannot be opened locally as files, but they are an 8-digit integer,
# the script will treat  them as a RIPE Atlas measurement IDs, and query RIPE for them)
%(prog)s 123456789 987654321

# Same as example 2, but list the results for ALL probes, instead of only the probes with results in BOTH measurements:
%(prog)s -a 123456789 987654321

# Same as example 2, but do NOT colorize the output:
%(prog)s -C 123456789 987654321

# Same as example 2, but set the threshold for significant latency differences to 10 instead of the default:
%(prog)s -l 10 123456789 987654321

# Same as example 2, but list ONLY the probes that take longer to respond than the threshold (see -S)
%(prog)s -s 123456789 987654321

# Same as the previous example, but list ONLY the probes that take more than 100 ms to respond
%(prog)s -s -S 100 123456789 987654321

# Compare one measurement's (12016241) for two points in time: 20210101_0000 and 20210301_0000.
%(prog)s --datetime1 20210101_0000 --datetime2 20210301_0000 12016241
''')
parser.add_argument('--datetime1', '--dt1', help=options_setup_dict_string['datetime1']['help'], type=str, default=config['datetime1'])
parser.add_argument('--datetime2', '--dt2', help=options_setup_dict_string['datetime2']['help'], type=str, default=config['datetime2'])
parser.add_argument('-a', '--all_probes', help=options_setup_dict_boolean['all_probes']['help'], action='store_true', default=config['all_probes'])
parser.add_argument('-c', '--color', '--colour', help=options_setup_dict_boolean['color']['help'], action="store_true", default=config['color'])
parser.add_argument('-C', '--no_color', '--no_colour', help=options_setup_dict_boolean['no_color']['help'], action="store_true", default=config['no_color'])
parser.add_argument('-e', '--emphasis_chars', help=options_setup_dict_boolean['emphasis_chars']['help'], action="store_true", default=config['emphasis_chars'])
parser.add_argument('-H', '--no_header', help=options_setup_dict_boolean['no_header']['help'], action="store_true", default=config['no_header'])
parser.add_argument('-i', '--dns_response_item_occurence_to_return', help=options_setup_dict_integer['dns_response_item_occurence_to_return']['help'], type=int, default=config['dns_response_item_occurence_to_return'])
parser.add_argument('-l', '--latency_diff_threshold', help=options_setup_dict_integer['latency_diff_threshold']['help'], type=int, default=config['latency_diff_threshold'])
parser.add_argument('-P', '--do_not_list_probes', help=options_setup_dict_boolean['do_not_list_probes']['help'], action='store_true', default=config['do_not_list_probes'])
parser.add_argument('-r', '--raw_probe_properties_file_max_age', help=options_setup_dict_integer['raw_probe_properties_file_max_age']['help'], type=int, default=config['raw_probe_properties_file_max_age'])
parser.add_argument('-s', '--list_slow_probes_only', help=options_setup_dict_boolean['list_slow_probes_only']['help'], action='store_true', default=config['list_slow_probes_only'])
parser.add_argument('-S', '--slow_threshold', help=options_setup_dict_integer['slow_threshold']['help'], type=int, default=config['slow_threshold'])
parser.add_argument('-t', '--split_char', help=options_setup_dict_string['split_char']['help'], type=str, default=config['split_char'])
parser.add_argument('-u', '--print_summary_stats', help=options_setup_dict_boolean['print_summary_stats']['help'], action='store_true', default=config['print_summary_stats'])
parser.add_argument('filename_or_msmid', help='one or two local filenames or RIPE Atlas Measurement IDs', nargs='+')
parser.format_help()
args = parser.parse_known_args()
### print (args[0]) ### debug
### print (args[0].split_char) ### debug
###exit()

# Put the remaining command line arguments into a list to process as files
# or measurement IDs.
data_sources = args[0].filename_or_msmid

# We need an idea of current unix time to decide if user-supplied
# date-times are good.
# First, let's figure out what the current unix time is in UTC.
current_unixtime = int(time.time())
# unix-time representation of config['oldest_atlas_result_datetime'], which is hardcoded up above.
oldest_result_unixtime = int(time.mktime(time.strptime(str(config['oldest_atlas_result_datetime']), '%Y %m %d %H:%M:%S')))

##################################################
#
# Function definitions
#
##########
# Return true if a supplied number falls in between now hours and
# config['oldest_atlas_result_datetime']
def is_valid_unixtime(_possible_unixtime):
    if isinstance(_possible_unixtime, int) and int(_possible_unixtime) < current_unixtime and int(_possible_unixtime) >= oldest_result_unixtime:
        return True
    else:
        ### sys.stderr.write(str(_possible_unixtime) + ' is not inbetween ' + str(oldest_result_unixtime) + ' and ' + str(current_unixtime) + '.\n')
        return False

##########
# Try a few formats to convert the datetime string they've supplied into unxitime
def user_datetime_to_valid_unixtime(user_dt_string):
    accepted_datetime_formats = [ '%Y%m%d', '%Y%m%d%H%M', '%Y%m%d_%H%M', '%Y%m%d_%H:%M',
                             '%Y%m%d %H%M', '%Y%m%d %H:%M', '%Y-%m-%d_%H%M', '%Y-%m-%d_%H:%M',
                             '%Y-%m-%d-%H%M', '%Y-%m-%d-%H:%M']
    if is_valid_unixtime(user_dt_string):
        return int(user_dt_string)
    # try to convert from a few similar formats
    for f in accepted_datetime_formats:
        try:
            # print (user_dt_string + ' / ' + f)
            _unixtime_candidate = int(time.mktime(time.strptime(user_dt_string, f)))
            if is_valid_unixtime(_unixtime_candidate):
                ### sys.stderr.write('Accepted %i as valid unixtime.\n' % _unixtime_candidate)
                return (_unixtime_candidate)
        except ValueError:
            ...
    # If fall out the bottom of the (above) for loop, then we do not have a valid time
    sys.stderr.write('Cannot validate "' + user_dt_string + '" as a date-time respresentation\n')
    exit(2)

# A list that might contain the user-supplied time period durations
# durations = [args[0].duration1, args[0].duration2 ]
# A list that might contain the unixtime respresentation of the user-supplied start times
unixtimes = [0, 0]

#####
# ansi formatting chars for fancy printing
class fmt:
    bold = '\033[1m'
    clear = '\033[0m'
    bright_green = '\033[92m'
    bright_red = '\033[91m'
    bright_yellow = '\033[93m'
    bright_magenta = '\033[95m'
####

#####
# initialize data structs
probe_measurement_rt = {}
measurement_probe_response_times = {}
addr_string = {}
asn_string = {}
measurement_ids = []
header_format = []
header_words = []
#
probe_detail_line_format_string = ''
probe_detail_header_format_string = ''
#probe_detail_line_output_color = []
#probe_detail_line_output_no_color = []

# We're expecting to process one or two sets of results for comparison.  Often,
# we're comparing two different measurement ids, but it's also possible to
# compare multiple sets of data called for the measurement id, so we
# create a results set id to organize and index the sets of results, instead of using
# the measurement id.
results_set_id = 0

# m_ are variables specific to measurement-sets
# p_ are variables specific to probes
# pm_ are variables specific to probe, per each measurement
#
# IP Address version --  some probe properties are either 4 or 6, like IP address or ASN
m_ip_version = {}
m_response_times = {}
m_timestamps = {}
m_total_response_time = {}
m_total_malformeds = {}
m_total_abuf_malformeds = {}
m_total_errors = {}
m_total_slow= {}
m_response_time_average = {}
m_response_time_std_dev = {}
m_total_responses = {}
#
# A dictionary for interesting properties associated with each probe, like
# their ASN, IP address, country, etc.
p_probe_properties = {}
#
pm_response_time = {}
pm_dns_server_substring = {}
#
m_seen_probe_ids = {}
m_seen_probe_ids_set = {}

# class probe_info:
#     '''
#     Class for Probe data this script might use
#     '''

#     def __init__(self, _id, address_v4, address_v6, asn_v4, asn_v6, prefix_v4, prefix_v6, country_code):
#         self._id = _id
#         self.address_v4 = address_v4
#         self.address_v6 = address_v6
#         self.asn_v4 = asn_v4
#         self.asn_v6 = asn_v6
#         self.prefix_v4 = prefix_v4
#         self.prefix_v6 = prefix_v6
#         self.country_code = country_code

#     def id(self):

# Validate the supplied date-times and stick them in a list
if args[0].datetime1 != 'None':
    unixtimes[0] = user_datetime_to_valid_unixtime(args[0].datetime1)
if args[0].datetime2 != 'None':
    unixtimes[1] = user_datetime_to_valid_unixtime(args[0].datetime2)

# Because this script is written to compare two measurement results, or
# just report one, this is kinda complicated:
#
# Set our last results set id to the length of the data_sources list.  (It
# should be either 0 or 1, but maybe this script will be modified to
# compare more than two sets of data, so try not to block that...)

# The args parsing setup should prevent this from happening, but just in
# case, exit here if we have zero data sources.
if len(data_sources) == 0:
    sys.stderr.write('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
    exit(3)
# They've supplied one msm or file...
elif len(data_sources) == 1:
    # ...so see how many timedates they supplied...
    if len(unixtimes) == 1:
        # If we reach here, we have one data source and only one datetime,
        # so only one set of results to show.
        last_results_set_id = 0
    # We have one data source and two times?
    elif len(unixtimes) == 2:
        # We set the second data source to be the same as the first,
        # otherwise the main loop would need logic to handle it being unset.
        data_sources.append(data_sources[0])
        last_results_set_id = 1
    # Somehow we have two many datetimes, so exit!
    else:
        sys.stderr.write('Please supply no more than two date times instead of %d.\n' % len(unixtimes))
        exit(3)
# They supplied two data sources:
elif len(data_sources) == 2:
    last_results_set_id = 1
#
#  They supplied something other than one or two data sources, which this script is not written to process.
else:
    sys.stderr.write('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
    exit(3)


####################
#
# Process the data, either from a local file or by requesting it over the
# 'net from RIPE Atlas.
#
def process_request(_data_source, _results_set_id, _unixtime):
    ### sys.stderr.write('Trying to access data_source %s for unixtime %s\n' % (_data_source, _unixtime))
    # First we try to open the _data_source as a local file.  If it exists,
    # read in the measurement results from a filename the user has
    # supplied.
    #
    # This code currently reads everything in, but it should be
    # modified to only load the data from the user-supplied time range,
    # if the user supplied one.
    try:
        f = open(_data_source, "r")
        results = json.load(f)
        f.close()
        if _unixtime != 0:
            sys.stderr.write('This script does not yet know how to read user-supplied time ranges out of local files.\n (But it can query the RIPE Atlas API for time ranges, so maybe you wanna do that instead?\n')
    except:
        ### sys.stderr.write('cannot read from file: %s\n' % _data_source)
        # If we are here, accessing _data_sources as a local file did not
        # work.  Next, we try to check to see if _data_source is an 8-digit
        # number.  If it is, then we assume it is an Atlas Measurement ID
        # and query their API with it.
        if re.match(r'^[0-9]{8}$', _data_source):
            # use it to make the request, but the measurement ID in the
            # returned data will be passed back to the code calling this
            # function, potentially redefining the measurement ID from
            # what the user supplied. (That really should not happen, but
            # the world is a weird place.)
            measurement_id = int(_data_source)
            # If we have no unixtime to request results from, then we get the latest results
            if _unixtime == 0:
                kwargs = {
                    "msm_id": measurement_id
                }
                ### sys.stderr.write('Fetching latest results for Measurement %i from RIPE Atlas API...\n' % measurement_id)
                is_success, results = AtlasLatestRequest(**kwargs).create()
            # We have a unixtime, so:
            # * use it as a start time
            # * add duration to it for the stoptime
            # * request the results
            else:
                measurement = Measurement(id=measurement_id)
                _stop_time = (_unixtime + measurement.interval - 300)
                kwargs = {
                    "msm_id": measurement_id,
                    "start": _unixtime,
                    "stop": _stop_time
                }
                ### sys.stderr.write('Fetching results for Measurement %i,  start unixtime: %s  stop unixtime: %s\n' % (measurement_id, _unixtime, _stop_time))
                is_success, results = AtlasResultsRequest(**kwargs).create()
            if not is_success:
                sys.stderr.write('Request of ' + _data_source + 'from RIPE Atlas failed.\n')
                exit(11)
        else:
            sys.stderr.write('Cannot read from ' + _data_source + ' and it does look like a RIPE Atlas Measurement ID\n')
            sys.exit(12)

    # Variables that start with a m_ are specific to measurements.
    # All of the m_* dictionaries are initalized at the top of the script.
    # Here, we are initializing the structure we will be writing into for this _results_set_id.
    # (results set identifier)
    m_ip_version[_results_set_id] = 0
    m_total_responses[_results_set_id] = 0
    m_total_response_time[_results_set_id] = 0
    m_total_malformeds[_results_set_id] = 0
    m_total_abuf_malformeds[_results_set_id] = 0
    m_total_errors[_results_set_id] = 0
    m_total_slow[_results_set_id] = 0
    m_response_time_average[_results_set_id] = 0
    m_response_time_std_dev[_results_set_id] = 0
    #
    m_response_times[_results_set_id] = []
    m_timestamps[_results_set_id] = []
    # The list of seen probe IDs for this measurentment-result-set
    m_seen_probe_ids[_results_set_id] = []


    # Loop through each (probe) result that come back from the call to DnsResult.
    for r in results:
        # this next line parses the data in r:
        dns_result = DnsResult(r, on_malformation=DnsResult.ACTION_IGNORE,
                               on_error=DnsResult.ACTION_IGNORE)
        # TODO: It's important to note that
        # 'on_error=DnsResult.ACTION_IGNORE' causes DnsResult to discard
        # std.err -- this script should be updated to catch and report
        # what's logged there.
        #
        # If the user supplied measurement ID(s) on the command line, we
        # already have them, but if they supplied filenames to read from,
        # we do not have one (or two).  So here, we read and (re-)define
        # the measurement_id, which is a tiny bit wasteful of CPU, but
        # cheaper than deciding if we should read it our of the result and
        # set measurement_id, or not.
        measurement_id = int(dns_result.measurement_id)
        # generate an response_set + probe_id to use as an index into
        # various dicts with responses
        results_and_probes_id = str(_results_set_id) + '-' + str(dns_result.probe_id)
        # Add the probe_id to the seen list.  We need to cast it to a
        # string, because the corresponding probe IDs in probe_info data
        # will be indexed by probe_id as a string.  (Because python.)
        m_seen_probe_ids[_results_set_id].append(str(dns_result.probe_id))
        m_total_responses[_results_set_id] += 1
        # Check for malformed responses or errors, and count them
        if dns_result.is_malformed:
            m_total_malformeds[_results_set_id] += 1
        elif dns_result.is_error:
            m_total_errors[_results_set_id] += 1
        else:
            # Even more (abuf) error checks...
            if dns_result.responses[0].abuf.is_malformed:
                m_total_abuf_malformeds[_results_set_id] += 1
            #            try dns_result.responses[1].get:
            if len(dns_result.responses) > 1: ### FIXME: Should this be 0 instead of 1?
                if dns_result.responses[1].abuf.is_malformed:
                    m_total_abuf_malformeds[_results_set_id] += 1
            # ... otherwise appended results to the dicts...
            m_response_times[_results_set_id].append(dns_result.responses[0].response_time)
            m_total_response_time[_results_set_id] += (dns_result.responses[0].response_time)
            if dns_result.responses[0].response_time > args[0].slow_threshold:
                m_total_slow[_results_set_id] += 1
            m_timestamps[_results_set_id].append(dns_result.created_timestamp)
            #
            pm_response_time[results_and_probes_id] = dns_result.responses[0].response_time

            # Not all of the DNS responses Atlas receives contain answers,
            # so we need to handle responses without them.
            try:
                dns_server_fqdn = dns_result.responses[0].abuf.answers[0].data[0]
                #
                # Split up the response text
                if args[0].split_char == '!':
                    split_result = dns_server_fqdn
                    ### sys.stderr.write('%s\n' % (dns_server_fqdn))
                else:
                    split_result = dns_server_fqdn.split(args[0].split_char)
                    if len(split_result) > args[0].dns_response_item_occurence_to_return:
                        pm_dns_server_substring[results_and_probes_id] = split_result[args[0].dns_response_item_occurence_to_return]
                    else:
                        pm_dns_server_substring[results_and_probes_id] = dns_server_fqdn
            except IndexError:
                pm_dns_server_substring[results_and_probes_id] = 'no_reply'
            except AttributeError:
                pm_dns_server_substring[results_and_probes_id] = 'no_data'

    measurement = Measurement(id=measurement_id)
    ### print(dir(measurement))
    m_ip_version[_results_set_id] = int(measurement.protocol)
    ### sys.stderr.write("Address family for measurement %i is %i\n" % (measurement_id, m_ip_version[_results_set_id]))

    # Sort some of the lists of results
    m_response_times[_results_set_id].sort()
    m_timestamps[_results_set_id].sort()
    m_seen_probe_ids[_results_set_id].sort()
    ### sys.stderr.write('m_seen_probe_ids[_results_set_id] is %d\n' % len(m_seen_probe_ids[_results_set_id]))
    return measurement_id

# END def process_request
####################

#####################
#
# Functions related to RIPE Atlas probe data
#
#####
# A) Why use a local cache?
# AFAICT, one can only request info about one probe at a time from the
# RIPE Atlas API, and that can be a slow, latentcy-ful process.
#
# B) Why are there two cache files?
#
# RIPE publishes a (daily?) updated version of all the probe data in one
# bz2-compressed file via HTTPS or FTP, so we can download that
# perdiodically.  The probe info is formatted as a 1-line JSON blob, that
# this script reads in and converts into a python dictionary.
#
# However, at the time of this writing (Apr. 2021) this file from RIPE
# seems to be missing information for many (like 35%+) of the probes.  So
# this script was subsequently modified to add into the probe info cache
# (dictionary) the additional info that's pulled down by via the Atlas
# API.
#
# This script then caches that "combined" dictionary as an uncompressed JSON file.
#
# So the first thing this function does is read in the probe properties
# JSON cache file, if it exists.  Then, if RIPE's raw file is newer, it
# loads into the prope properties dictionary the data from RIPE's
# (probably just downloaded) file on top of the cached file.  Then it
# writes out that dictionary as a JSON file, for use next time.
#
def check_update_probe_properties_cache_file(pprf, ppcf, ppurl):
    all_probes_dict = {}
    # If the probe properties cache file exists, read it into the all probes dictionary.
    try:
        ppcf_statinfo = os.stat(ppcf)
        ppcf_age = int(ppcf_statinfo.st_mtime)
        ### sys.stderr.write('Reading in existing local JSON cache file %s...\n' % ppcf)
        with open(ppcf, 'r') as f:
            all_probes_dict = json.load(f)
    except:
        # The cache file does not seem to exist, so set the age to
        # zero, to trigger rebuild.
        ### sys.stderr.write('Local JSON cache file %s does not exist; generating it.\n' % ppcf)
        ppcf_age = -1

    try:
        # Check to see if the raw file (that's downloaded from RIPE)
        # exists, and if so get its last mtime.
        pprf_statinfo = os.stat(pprf)
        pprf_age = int(pprf_statinfo.st_mtime)
    except:
        # The raw file does not seem to exist, so set the age to zero,
        # and assume the age evaluation will try trigger a download.
        pprf_age = 0

    # Check to see if the current time minus the raw file age is more than the expiry
    if ((current_unixtime - pprf_age) > int(config['raw_probe_properties_file_max_age'])):
        # Fetch a new raw file, and generate the JSON format cache file
        try:
            ### sys.stderr.write ('%s is out of date, so trying to fetch fresh probe data from RIPE...\n' % pprf)
            urlretrievefilename, headers = urllib.request.urlretrieve(ppurl, filename=pprf)
            html = open(pprf)
            html.close()
        except:
            sys.stderr.write('Cannot urlretrieve %s -- continuing without updating %s \n' %
             (ppurl, pprf))
            os.replace(pprf + '.old', pprf)
            return(2)

    # If the raw file is newer than the local JSON cache file, decompress
    # and read it in on top of the probe properties cache dictionary.
    if ppcf_age < pprf_age:
        try:
            all_probes_list = json.loads(bz2.BZ2File(pprf).read().decode()).get('objects')
        except:
            sys.stderr.write ('Cannot read raw probe data from file: %s\n' % pprf)
            return(1)
            # What we end up with in all_probes_list is a python list, but a
            # dictionary would be much more efficient keyed on the probe id would
            # be much more efficient, so we're going to burn some electricity and
            # convert the list into a dictionary.
        ### sys.stderr.write ('Converting the RIPE Atlas probe data into a dictionary and indexing it...\n')
        while len(all_probes_list) > 0:
            probe_info = all_probes_list.pop()
            probe_id = str(probe_info['id'])
            all_probes_dict[probe_id] = probe_info
            ### pprint (all_probes_dict.keys())
        # now save that dictionary as a JSON file...
        ### sys.stderr.write ('Saving the probe data dictionary as a JSON file at %s...\n' % ppcf)
        with open(ppcf, 'w') as f:
            json.dump(all_probes_dict, f)
    ### sys.stderr.write('%s does not need to be updated.\n' % pprf)
    return(0)
#
# END def check_update_probe_properties_cache_file
#
#####
#
# Return probe properties for one probe (Requires RIPE Atlas cousteau
# library) def report_probe_properties(prb_id): return
# (p_probe_properties[prb_id)) END def report_probe_properties
####################
#
# Load the probe properties, either from the cache or by requesting them from RIPE.
def load_probe_properties(probe_ids, ppcf):
    probe_cache_hits = 0
    probe_cache_misses = 0
    matched_probe_info = {}
    all_probes_dict = {}
    #
    ### sys.stderr.write ('Reading the probe data dictionary as a JSON file from %s...\n' % ppcf)
    try:
        with open(ppcf, 'r') as f:
            all_probes_dict = json.load(f)
    except:
        sys.stderr.write ('Cannot read probe data from file: %s\n' % ppcf)
        exit(13)
    # Loop through the list of supplied (seen) probe ids and collect their
    # info/meta data from either our local file or the RIPE Atlas API
    ### sys.stderr.write ('Matching seen probes with probe data; will query RIPE Atlas API for probe info not in local cache...\n')
    for p in probe_ids:
        ### sys.stderr.write ('Searching for info about probe %9s ... ' % p)
        if p in all_probes_dict.keys():
            probe_cache_hits += 1
            ### sys.stderr.write ('FOUND in local cache.\n')
            matched_probe_info[p] = all_probes_dict[p]
        else:
            # If it's not in the cache file, request it from RIPE
            #### sys.stderr.write ('NOT cached, trying RIPE Atlas...')
            try:
                ripe_result = Probe(id=p)
                #
                matched_probe_info[p] = {'asn_v4': ripe_result.asn_v4,
                                         'asn_v6': ripe_result.asn_v6,
                                         'country_code': ripe_result.country_code,
                                         'address_v4':  ripe_result.address_v4,
                                         'address_v6':  ripe_result.address_v6}
                probe_cache_misses += 1
                all_probes_dict[p] = matched_probe_info[p]
                ### sys.stderr.write (' success!\n')
            except:
                # Otherwise, it's empty
                ### sys.stderr.write (' fail :(\n')
                # we did not find any information about the probe, so set values to '-'
                matched_probe_info[p] = { 'asn_v4': '-',
                                          'asn_v6': '-',
                                          'country_code': '-',
                                          'address_v4': '-',
                                          'address_v6': '-' }
                ### sys.stderr.write ('Could not get info about probe ID %s in the local cache or from RIPE Atlas API \n' % p)
    ### sys.stderr.write ('cache hits: %i   cache misses: %i.\n' % (probe_cache_hits, probe_cache_misses))
    # Write out the local JSON cache file
    with open(ppcf, mode='w') as f:
        json.dump(all_probes_dict, f)
    return(matched_probe_info)


# END of all function defs
##################################################

######
#
# Data loading and summary stats reporting loop ...
while results_set_id <= last_results_set_id:
#for t in data_sources:
    # m will receive the measurment ID for the processed data source
    ### sys.stderr.write('data_source: %s  results_set_id: %i  unixtime: %i\n' % (data_sources[results_set_id], results_set_id, unixtimes[results_set_id]))
    m = process_request(data_sources[results_set_id], results_set_id, unixtimes[results_set_id])
    measurement_ids.append(m)
    ######
    # Summary stats
    if args[0].print_summary_stats:
        # generate some summary stats
        m_response_time_average[results_set_id] = statistics.fmean(m_response_times[results_set_id])
        m_response_time_std_dev[results_set_id] = statistics.pstdev(m_response_times[results_set_id])
        print()
        print('%37s %10i' % ('Result set:', results_set_id))
        print('%37s %10i' % ('Measurement_ID:', m))
        print('%37s %10i' % ('Total Responses:', m_total_responses[results_set_id]))
        if args[0].list_slow_probes_only:
            slow_string = 'Slow (>' + str(args[0].slow_threshold) + 'ms) responses:'
            print('%37s %10i' % (slow_string, m_total_slow[results_set_id]))
            print('%37s %10i' % ('Errors:', m_total_errors[results_set_id]))
            print('%37s %10i' % ('Malformed Responses:', m_total_malformeds[results_set_id]))
            print('%37s %10i' % ('Malformed Answer Buffers:', m_total_abuf_malformeds[results_set_id]))
            print('%37s %19s - %19s' % ('Measurements created time range:',
                    time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(m_timestamps[results_set_id][0])),
                    time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(m_timestamps[results_set_id][-1]))))
            print('%37s %4.3f/%4.3f/%4.3f/%4.3f' % ('reponse time (ms) min/avg/max/stddev:',
                                                m_response_times[results_set_id][0],
                                                m_response_time_average[results_set_id],
                                                m_response_times[results_set_id][-1],
                                                m_response_time_std_dev[results_set_id]))
    # End of Summary stats printing
    ######
    # Build a unique set of probes that responded per set
    # as many as 2x duplicates).
    m_seen_probe_ids_set[results_set_id] = set(m_seen_probe_ids[results_set_id])
    #
    results_set_id += 1
# end of Data loading and summary stats reporting loop

########################################

# Check to see if there are two sets of results.  If there are, see if
# there are probes common to the two sets, and if there are not any in
# common, then exit.
# Default IP version to expect is 4
report_ip_version = 4
if last_results_set_id > 0:
    ### print (m_seen_probe_ids_set[0])
    ### print (m_seen_probe_ids_set[1])
    if m_seen_probe_ids_set[0].isdisjoint(m_seen_probe_ids_set[1]):
        sys.stderr.write('The two sets of measurement results do not have any probes in common.\n')
        sys.stderr.write('Set 0: ')
        for p in m_seen_probe_ids_set[0]:
            sys.stderr.write(p + ' ')
        sys.stderr.write('\nSet 1: ')
        for p in m_seen_probe_ids_set[1]:
            sys.stderr.write(p + ' ')
        sys.stderr.write('\n')
        exit(14)
    # if there are probes in common, build a uniq set of all probe ids
    # seen in both sets of measurements, and a list of common probe IDs
    else:
        common_probe_ids = list(m_seen_probe_ids_set[0].intersection(m_seen_probe_ids_set[1]))
        uniq_seen_probe_ids = list(m_seen_probe_ids_set[0].union(m_seen_probe_ids_set[1]))

    # Measurement are requested for or a version of IP (v4 or v6).  As
    # this script can compare two measurements, it's possible that the
    # user has asked us to compare measurements that are for different IP
    # versions, which is probably not very useful, and creates some
    # trouble for displaying per-probe data, like IP addresses or ASNs.
    # So:
    # - warn the user if the versions are different, and set the display data to be v4 (default is above)
    # - otherwise, display the data common version
    if m_ip_version[0] != m_ip_version[1]:
        sys.stderr.write('WARNING: Measurements %i and %i were made for two different address families: %i vs. %i.\n  Only v4 probe info (ASN, IP address) will be displayed.\n'
                         % (measurement_ids[0], measurement_ids[1], m_ip_version[0], m_ip_version[1]))
    else:
        report_ip_version = m_ip_version[0]

# Only one set of results, so use its uniq set of the seen probe IDs.
else:
    uniq_seen_probe_ids = list(m_seen_probe_ids_set[0])
    common_probe_ids = uniq_seen_probe_ids

##################################################
#
# Printing output is very complicated.
#
# If we are printing out detailed (per-probe) stats, we do what's below...
# By default, we list each probe's properties.
if not args[0].do_not_list_probes:
    # figure out which probes they want to see... intersection or union?
    if args[0].all_probes:
        probe_ids_to_list = uniq_seen_probe_ids
    else:
        probe_ids_to_list = common_probe_ids
    # Check (and maybe update) the local probes' properties cache file.
    _res = check_update_probe_properties_cache_file(config['ripe_atlas_probe_properties_raw_file'],
                                                     config['ripe_atlas_probe_properties_json_cache_file'],
                                                     config['ripe_atlas_current_probe_properties_url'])
    if _res != 0:
        sys.stderr.write('Unexpected result when updating local cache files: %s\n' % _res)
    p_probe_properties = load_probe_properties(probe_ids_to_list,
                                       config['ripe_atlas_probe_properties_json_cache_file'])
    if not args[0].no_header:
        header_label = [None, None]
        # Set the header labels based on what we're comparing (msm_ids or dates)
        #  If there are two dates, we want those as the header labels
        if args[0].datetime2 != None:
            ### print ('hasattr datetime2')
            header_label[0] = str(args[0].datetime1) + '(ms)'
            header_label[1] = str(args[0].datetime2) + '(ms)'
        #  Otherwise, if there are two msm_ids, we want those as the header labels
        elif len(measurement_ids) == 2:
            header_label[0] = str(measurement_ids[0]) + '(ms)'
            header_label[1] = str(measurement_ids[1]) + '(ms)'
        # Last, we just use the one msm_id
        else:
            header_label[0] = str(measurement_ids[0]) + '(ms)'
            header_label[1] = ''
    # Figure out how wide the text field should be for the IP address, depending upon the IP version.
    if report_ip_version == 4:
        address_width = 15
    elif report_ip_version == 6:
        address_width = 39
    else:
        sys.stderr.write('Do not know what to set address width for IP version %i.\n' % report_ip_version)
        address_width = 0
    # Build the formatted-output per-probe and header lines from the list of (user-configurable) properties.
    for pp in probe_properties_to_report:
        fmt_string_a = 'f_' + pp
        if pp == 'probe_id':
            fmt_string_b = '>12s'
            header_words.append(pp)
            header_format.append('{:>12s}')
        elif pp == 'asn':
            fmt_string_b = '>10s'
            header_words.append('ASN')
            header_format.append('{:>10s}')
        elif pp == 'country_code':
            fmt_string_b = '>2s'
            header_words.append('CC')
            header_format.append('{:>2s}')
        elif pp == 'ip_address':
            fmt_string_b = '>' + str(address_width) + 's'
            header_words.append(pp)
            header_format.append('{:>' + str(address_width) + 's}')
        elif pp == 'rt_a':
            item_size = len(header_label[0])
            header_words.append(str(header_label[0]))
            header_format.append('{:>13s}')
            fmt_string_a = 'f_rt_a_fmt_chars:s}{f_' + pp
            if item_size > 13:
                fmt_string_b = '>' + str(item_size) + 'f'
            else:
                fmt_string_b = '>13.2f'
            fmt_string_b += '}{f_fmt_clear:s'
        elif pp == 'rt_b':
            item_size = len(header_label[1])
            header_words.append(str(header_label[1]))
            header_format.append('{:>13s}')
            fmt_string_a = 'f_rt_b_fmt_chars:s}{f_' + pp
            if item_size > 13:
                fmt_string_b = '>' + str(item_size) + 'f'
            else:
                fmt_string_b = '>13.2f'
            fmt_string_b += '}{f_fmt_clear:s'
        elif pp == 'rt_diff':
            header_words.append('diff(ms) ')
            header_format.append('{:>8s}')
            fmt_string_a = 'f_rt_diff_fmt_chars:s}{f_' + pp
            fmt_string_b = '>8.2f}{f_rt_emph_char:s}{f_fmt_clear:s'
        elif pp == 'dns_response':
            header_words.append('DNSSrvsubstr[:B] ')
            header_format.append('{:>15s}')
            fmt_string_a = 'f_sites_fmt_chars:s}{f_' + pp
            fmt_string_b = '15s}{f_sites_emph_char:s}{f_fmt_clear:s'
        else:
            sys.stderr.write('Unknown probe paramter: %s\n' % pp)
        probe_detail_line_format_string += '{' + fmt_string_a + ':' + fmt_string_b + '} '
    #
    probe_detail_line_format_string += '{f_fmt_clear:s}'
    #
    # Print the header lines, unless the were supressed by the user.
    if not args[0].no_header:
        header_string = ''
        for align, text in zip(header_format, header_words):
            header_string += (align.format(text) + ' ')
        sys.stderr.write(header_string + '\n')
        sys.stderr.write('-' * len(header_string) + '\n')
    # Iterate over the list of probe ids to lis, then print out the
    # results per result set.
    ### print (probe_ids_to_list)
    ### print(probe_detail_line_format_string)
    for probe_id in probe_ids_to_list:
        #if probe_id is None:
        #    break
        ### print('{f_probe_id:s}'.format(f_probe_id=probe_id))
        #
        # Prepare what will be printed based on result set.
        # Probes can have v4 or v6 ASNs and IP addresses.  By default we show v4, unless BOTH measurements were v6
        p_probe_properties[probe_id]['display_asn'] = p_probe_properties[probe_id].get('asn_v4','-')
        p_probe_properties[probe_id]['display_address'] = p_probe_properties[probe_id].get('address_v4','-')
        if report_ip_version == 6:
            p_probe_properties[probe_id]['display_asn'] = p_probe_properties[probe_id].get('asn_v6','-')
            p_probe_properties[probe_id]['display_address'] = p_probe_properties[probe_id].get('address_v6','-')
        if p_probe_properties[probe_id]['display_asn'] is None:
            p_probe_properties[probe_id]['display_asn'] = '-'
        if p_probe_properties[probe_id]['display_address'] is None:
            p_probe_properties[probe_id]['display_address'] = '-'
        if p_probe_properties[probe_id]['country_code'] is None:
            p_probe_properties[probe_id]['country_code'] = '-'
        ### print(probe_id, p_probe_properties[probe_id]['display_address'])
        # generate an response_set + probe_id to use as an index into
        # various dicts with responses
        results_and_probes_id = str(0) + '-' + str(probe_id)
        next_results_and_probes_id = str(1) + '-' + str(probe_id)
        rt_a = float(pm_response_time.setdefault(results_and_probes_id, -1))
        rt_b = float(pm_response_time.setdefault(next_results_and_probes_id, -1))
        rt_a_fmt_chars = fmt.clear
        rt_b_fmt_chars = fmt.clear
        sites_fmt_chars = fmt.clear
        rt_emph_char = ' '
        sites_emph_char = ' '
        rt_fmt_chars = fmt.clear
        if rt_a > 0 and rt_b > 0:
            rt_diff = rt_b - rt_a
        else:
            rt_diff = 0
        if rt_diff > args[0].latency_diff_threshold:
            rt_diff_fmt_chars = fmt.bold + fmt.bright_red
            if args[0].emphasis_chars:
                rt_emph_char = '*'
        elif rt_diff < (args[0].latency_diff_threshold * -1 ):
            rt_diff_fmt_chars = fmt.bold + fmt.bright_green
        elif rt_diff == 0:
            rt_diff_fmt_chars = fmt.bright_magenta
        else:
            rt_diff_fmt_chars = fmt.clear
            if args[0].emphasis_chars:
                rt_emph_char = ' '
        if pm_dns_server_substring.setdefault(results_and_probes_id, 'unknown') == pm_dns_server_substring.setdefault(next_results_and_probes_id, 'unknown'):
            sites_string = pm_dns_server_substring[results_and_probes_id]
            sites_fmt_chars = fmt.clear
            if args[0].emphasis_chars:
                sites_emph_char = ' '
        else:
            sites_string = pm_dns_server_substring[results_and_probes_id] + ':' + pm_dns_server_substring[next_results_and_probes_id]
            sites_fmt_chars = fmt.bold + fmt.bright_red
            if args[0].emphasis_chars:
                sites_emph_char = '!'
            # Printing output is complicated.
        if not args[0].list_slow_probes_only or (args[0].list_slow_probes_only and ((rt_a > args[0].slow_threshold) or (rt_b > args[0].slow_threshold))):
            # Slow sites are yellow, and non-responding sites (we
            # set to -1) get magenta
            if args[0].no_color:
                rt_a_fmt_chars = ''
                rt_b_fmt_chars = ''
                sites_fmt_chars = ''
                format_clear = ''
            else:
                if rt_a > args[0].slow_threshold:
                    rt_a_fmt_chars = fmt.bright_yellow
                elif rt_a < 0:
                    rt_a_fmt_chars = fmt.bright_magenta
                if rt_b > args[0].slow_threshold:
                    rt_b_fmt_chars = fmt.bright_yellow
                elif rt_b < 0:
                    rt_b_fmt_chars = fmt.bright_magenta
                # Sites differed between the two tests: highlight RED
                if re.match(r'.*:.*', sites_string, flags=re.IGNORECASE):
                    sites_fmt_chars != fmt.bright_red
                # Sites the same across tests, but both unknown: highlight MAGENTA
                elif re.match(r'unknown', sites_string, flags=re.IGNORECASE):
                    sites_fmt_chars = fmt.bright_magenta
                # Sites the same across tests, but both no_reply: highlight yellow
                elif re.match(r'no_reply', sites_string, flags=re.IGNORECASE):
                    sites_fmt_chars = fmt.bright_yellow
                # should already be clear, but just in case...
                else:
                    sites_fmt_chars = fmt.clear
                format_clear = fmt.clear
            # try:
            print(probe_detail_line_format_string.format(f_probe_id=probe_id,
                                                         f_asn=str(p_probe_properties[probe_id]['display_asn']),
                                                         f_country_code=p_probe_properties[probe_id]['country_code'],
                                                         f_ip_address=p_probe_properties[probe_id]['display_address'],
                                                         f_rt_a_fmt_chars=rt_a_fmt_chars,
                                                         f_rt_a=rt_a,
                                                         f_rt_b_fmt_chars=rt_b_fmt_chars,
                                                         f_rt_b=rt_b,
                                                         f_rt_diff_fmt_chars=rt_diff_fmt_chars,
                                                         f_rt_diff=rt_diff,
                                                         f_rt_emph_char=rt_emph_char,
                                                         f_sites_fmt_chars=sites_fmt_chars,
                                                         f_dns_response=sites_string,
                                                         f_sites_emph_char=sites_emph_char,
                                                         f_fmt_clear=format_clear))
            # except:
            #     sys.stderr.write("There is something unexpected in this probe info: ")
            #     for a in (probe_id,
            #               str(p_probe_properties[probe_id]['display_asn']),
            #               p_probe_properties[probe_id]['country_code'],
            #               p_probe_properties[probe_id]['display_address'],
            #               rt_a_fmt_chars,
            #               rt_a,
            #               rt_b_fmt_chars,
            #               rt_b,
            #               rt_diff_fmt_chars,
            #               rt_diff,
            #               rt_emph_char,
            #               sites_fmt_chars,
            #               sites_string,
            #               sites_emph_char,
            #               format_clear):
            #         sys.stderr.write(str(a) + ' | ')
            #     sys.stderr.write('\n')
