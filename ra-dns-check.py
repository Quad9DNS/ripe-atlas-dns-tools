#!/usr/bin/env python3
#
# ra-dns-check.py, v2.2
#
# Parse, summarize, sort, and display RIPE Atlast measurement results for DNS queries

# Please see the file LICENSE for the license.

import argparse
# need ast to more safely parse config file
import ast
import configparser
import json
import logging
import mmap
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
# These RIPE python modules are usually installed with pip:
from ripe.atlas.cousteau import AtlasLatestRequest
from ripe.atlas.cousteau import AtlasResultsRequest
from ripe.atlas.cousteau import Probe
from ripe.atlas.sagan import DnsResult
from ripe.atlas.cousteau import Measurement
# for debugging
from pprint import pprint

#
# Valid log levels
valid_log_levels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']

# Change "CRITICAL" to DEBUG if you want debugging-level logging *before* this
# script parses command line args, and subsequently sets the debug level:
logging.basicConfig(level=logging.CRITICAL)

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
# default, ConfigParser reads everything in as a string, but there are
# ways to read specific sections or values as int or bool.

# A list of "legal" probe properties that can be reported.
reportable_probe_properties = ['probe_id', 'asn', 'country_code', 'ip_address', 'rt_a', 'rt_b', 'rt_diff', 'dns_response']

#
# Comment header (help) for the config file. If the config file does not
# exist, this script creates it from this string plus the preceding
# options_sample_dict_* dicts.
#
# Options specified in the config file can then also be overridden by what's specified on the command line.
#
sample_config_string_header = """;
; Config file for ra-dns-check.py
;
; This file is automatically created if it does not exist.  After its
; initial creation, the script will add missing parameters to this config
; file, but otherwise should not overwrite any changes you make!  (If you
; ever want to reset everything to the script defaults, you can rename or
; delete this file and the script will create a new one.)
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
; 2) Do not remove or change the [DEFAULT] line, python's ConfigParser module depends upon it.
;
;;;;;;;;;;;;;;;;;;;;
[DEFAULT]
"""

# Define variable-type-specific sections of the config.
# The reasons we have these sections:
# 1) Python's ConfigParser module requires at least one section.
# 2) ConfigParser reads in all of the config values as strings.  So by
#    grouping them by type in the config, it's easier "up front" to loop
#    through and cast them to the correct types, and then not worry about
#    remembering to do the cases later as they get used.

options_sample_dict = {
    'datetime1': {
        'default': None,
        'help': 'date-time to start 10-minute period for FIRST set of results (UTC).\n; Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")',
        'type': 'string'},
    'datetime2': {
        'default': None,
        'help': 'date-time to start 10-minute period for SECOND set of results (UTC).\n;  Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")',
        'type': 'string'},
    'log_level': {
        'default': 'WARN',
        'help': 'The level of logging (debugging) messages to show. One of:' + str(valid_log_levels) + ' (default is WARN)',
        'type': 'string'},
    'oldest_atlas_result_datetime': {
        'default': '2010 01 01 00:00:00',
        'help': ' Wikipedia says 2010 was when RIPE Atlas was established, so we use that\n; as a starting point for when it might contain some data.',
        'type': 'string'},
    'probe_properties_to_report': {
        'default': reportable_probe_properties,
        'help': 'The list of probe properties to report. Must be a subset of:\n;  ' + str(reportable_probe_properties),
        'type': 'string'},
    'ripe_atlas_probe_properties_raw_file': {
        'default': os.environ['HOME'] + '/.RIPE_atlas_all_probe_properties.bz2',
        'help': 'There are a couple of files used to locally cache probe data, the first comes directly from RIPE:',
        'type': 'string'},
    'ripe_atlas_probe_properties_json_cache_file': {
        'default': os.environ['HOME'] + '/.RIPE_atlas_probe_properties_cache_file.json',
        'help': 'The second cache file we generate, based upon probe info we request (one at a time) from the RIPE Atlas API.',
        'type': 'string'},
    'ripe_atlas_current_probe_properties_url': {
        'default': 'https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest',
        'help': 'Where to fetch the RA probe properties file from.',
        'type': 'string'},
    'split_char': {
        'default': '.',
        'help': 'character (delimiter) to split the string on (can occur in the string more than once.',
        'type': 'string'},
    'all_probes': {
        'default': False,
        'help': 'show information for probes present in *either* result sets, not just those present in *both* sets',
        'type': 'boolean'},
    'color': {
        'default': True,
        'help': 'colorize output',
        'type': 'boolean'},
    'no_color': {
        'default': False,
        'help': 'do NOT colorized output (AKA "colourised output")',
        'type': 'boolean'},
    'emphasis_chars': {
        'default': False,
        'help': 'add a trailing char (! or *) to aberrant sites and response times',
        'type': 'boolean'},
    'no_header': {
        'default': False,
        'help': 'Do NOT show the header above the probe list',
        'type': 'boolean'},
    'do_not_list_probes': {
        'default': False,
        'help': 'do NOT list the results for each probe',
        'type': 'boolean'},
    'list_slow_probes_only': {
        'default': False,
        'help': 'in per-probe list,show ONLY the probes reporting response times',
        'type': 'boolean'},
    'print_summary_stats': {
        'default': False,
        'help': 'show summary stats',
        'type': 'boolean'},
    'dns_response_item_occurence_to_return': {
        'default': 1,
        'help': 'Which item to return from the split-list. First element is 0. Default: 1',
        'type': 'integer'},
    'latency_diff_threshold': {
        'default': 5,
        'help': 'the amount of time difference (ms) that is significant when comparing latencies between tests. Default: 5',
        'type': 'integer'},
    'slow_threshold': {
        'default': 50,
        'help': 'Response times (ms) larger than this trigger color highlighting. Default: 50',
        'type': 'integer'},
    'raw_probe_properties_file_max_age': {
        'default': 86400,
        'help': 'The max age (seconds) of the RIPE Atlas probe info file (older than this and we download a new one). Default: 86400',
        'type': 'integer'},
    'exclusion_list_file': {
        'default': None,
        'help': 'Filename for probe ID exclusion list',
        'type': 'string'},
}

sample_config_string = sample_config_string_header
expected_config_items = options_sample_dict.keys()
# Iterate over the items in the options_sample_dict (defined above)
# and shove them into the big string "sample_config_dict" that will then be fed to ConfigParser.
for k in expected_config_items:
    sample_config_string += (';\n')
    sample_config_string += ('; ' + options_sample_dict[k]['help'] + '\n')
    sample_config_string += (k + ' = ' + str(options_sample_dict[k]['default']) + '\n')

logging.debug(sample_config_string)

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
parser.add_argument('--datetime1', '--dt1', help=options_sample_dict['datetime1']['help'], type=str, default=options_sample_dict['datetime1']['default'])
parser.add_argument('--datetime2', '--dt2', help=options_sample_dict['datetime2']['help'], type=str, default=options_sample_dict['datetime2']['default'])
parser.add_argument('-a', '--all_probes', help=options_sample_dict['all_probes']['help'], action='store_true', default=options_sample_dict['all_probes']['default'])
parser.add_argument('-c', '--color', '--colour', help=options_sample_dict['color']['help'], action="store_true", default=options_sample_dict['color']['default'])
parser.add_argument('-C', '--no_color', '--no_colour', help=options_sample_dict['no_color']['help'], action="store_true", default=options_sample_dict['no_color']['default'])
parser.add_argument('-e', '--emphasis_chars', help=options_sample_dict['emphasis_chars']['help'], action="store_true", default=options_sample_dict['emphasis_chars']['default'])
parser.add_argument('-E', '--exclusion_list_file', help=options_sample_dict['exclusion_list_file']['help'], type=str, default=options_sample_dict['exclusion_list_file']['default'])
parser.add_argument('-f', '--config_file', help='Read (and write) the config from specified file', type=str, default=my_config_file)
parser.add_argument('-H', '--no_header', help=options_sample_dict['no_header']['help'], action="store_true", default=options_sample_dict['no_header']['default'])
parser.add_argument('-i', '--dns_response_item_occurence_to_return', help=options_sample_dict['dns_response_item_occurence_to_return']['help'], type=int, default=options_sample_dict['dns_response_item_occurence_to_return']['default'])
parser.add_argument('-l', '--latency_diff_threshold', help=options_sample_dict['latency_diff_threshold']['help'], type=int, default=options_sample_dict['latency_diff_threshold']['default'])
parser.add_argument('--log_level', help=options_sample_dict['log_level']['help'], type=str, choices=valid_log_levels, default=options_sample_dict['log_level']['default'])
parser.add_argument('--oldest_atlas_result_datetime', help=options_sample_dict['oldest_atlas_result_datetime']['help'], type=str, default=options_sample_dict['oldest_atlas_result_datetime']['default'])
parser.add_argument('-P', '--do_not_list_probes', help=options_sample_dict['do_not_list_probes']['help'], action='store_true', default=options_sample_dict['do_not_list_probes']['default'])
parser.add_argument('--probe_properties_to_report', help=options_sample_dict['probe_properties_to_report']['help'], type=str, default=options_sample_dict['probe_properties_to_report']['default'])
parser.add_argument('-r', '--raw_probe_properties_file_max_age', help=options_sample_dict['raw_probe_properties_file_max_age']['help'], type=int, default=options_sample_dict['raw_probe_properties_file_max_age']['default'])
parser.add_argument('--ripe_atlas_current_probe_properties_url', help=options_sample_dict['ripe_atlas_current_probe_properties_url']['help'], type=str, default=options_sample_dict['ripe_atlas_current_probe_properties_url']['default'])
parser.add_argument('--ripe_atlas_probe_properties_json_cache_file', help=options_sample_dict['ripe_atlas_probe_properties_json_cache_file']['help'], type=str, default=options_sample_dict['ripe_atlas_probe_properties_json_cache_file']['default'])
parser.add_argument('--ripe_atlas_probe_properties_raw_file', help=options_sample_dict['ripe_atlas_probe_properties_raw_file']['help'], type=str, default=options_sample_dict['ripe_atlas_probe_properties_raw_file']['default'])
parser.add_argument('-s', '--list_slow_probes_only', help=options_sample_dict['list_slow_probes_only']['help'], action='store_true', default=options_sample_dict['list_slow_probes_only']['default'])
parser.add_argument('-S', '--slow_threshold', help=options_sample_dict['slow_threshold']['help'], type=int, default=options_sample_dict['slow_threshold']['default'])
parser.add_argument('-t', '--split_char', help=options_sample_dict['split_char']['help'], type=str, default=options_sample_dict['split_char']['default'])
parser.add_argument('-u', '--print_summary_stats', help=options_sample_dict['print_summary_stats']['help'], action='store_true', default=options_sample_dict['print_summary_stats']['default'])
parser.add_argument('filename_or_msmid', help='one or two local filenames or RIPE Atlas Measurement IDs', nargs='+')
parser.format_help()
args = parser.parse_known_args()
###pprint(args)

logger = logging.getLogger()
logger.setLevel(args[0].log_level)


####################
#
# Config file parse
#
my_config_file = args[0].config_file
raw_config = configparser.ConfigParser()
config_file_read = False
write_config_file = False
try:
    if os.stat(my_config_file):
        if os.access(my_config_file, os.R_OK):
            logger.info('Found config file at %s; reading it now...\n' % my_config_file)
            ro_cf = open(my_config_file, 'r')
            config_file_string = ro_cf.read()
            logger.debug(type(config_file_string))
            logger.debug('config_file_string:')
            logger.debug(config_file_string)
            if re.search('STRING', config_file_string, re.MULTILINE):
                old_style_cf = my_config_file + '.old-style'
                logger.warning('Old-style config file found; it will be moved to %s' % old_style_cf)
                logger.warning('A new-style config file with default values written at %s' % my_config_file)
                os.rename(my_config_file,old_style_cf)
                config_file_read = False
                write_config_file = True
            else:
                raw_config.read_string(config_file_string)
                config_file_read = True
        else:
            logger.critical('Config file exists at %s, but is not readable.\n' % my_config_file)
except FileNotFoundError:
    logger.info('Config file does not exist at %s; will create a new one...\n' % my_config_file)
    write_config_file = True
if not config_file_read:
    raw_config.read_string(sample_config_string)

raw_config_options = set(raw_config['DEFAULT'].keys())

# This 'config' dict stores the merged config (from the config file and the sample above).
config = {}

#options_from_config_file = []

#logger.debug(raw_config.sections())

# If we read the a config file Loop through what's in the sample config
# and see if any items are missing from what was read from the config
# file.  (Like if we've added some settings to the script, and it's
# reading in an older, pre-existing config file for the first time
# since the new option was added.)
if config_file_read:
    logger.debug('options_sample_dict:')
    logger.debug(set(options_sample_dict))
    logger.debug('raw_config_options:')
    logger.debug(set(raw_config_options))
    for opt in (set(options_sample_dict) - set(raw_config_options)):
        logger.info('%s missing from config file; setting it to default from script: %s' %
                     (opt, options_sample_dict[opt]['default']))
        config[opt] = options_sample_dict[opt]['default']
        write_config_file = True

#
# Loop through what's in the raw config and see if each variable is in
# the (following) list of expected config variables, so we can catch
# any unexpected ("illegal") parameters in the config file, rather
# than let a typo or some bit of random (non-comment) text in the
# config file go unnoticed.
for item in raw_config_options:
    logger.debug('Checking %s to see if it is known...' % item)
    if item in expected_config_items:
        if getattr(args[0], item) != options_sample_dict[item]['default']:
            config[item] = getattr(args[0], item)
        else:
            config[item] = raw_config['DEFAULT'].get(item)
    else:
        logger.critical('Unknown parameter in config file: %s\n' % item)
        exit(1)

# Write out the config file
if write_config_file:
    config_string_to_write = sample_config_string_header
    # Iterate over the items in the three options_sample_dict_* (defined above)
    # and shove them into the big string "sample_config_string" that will then be fed to ConfigParser.
    for k in options_sample_dict.keys():
        logger.debug('adding config item %s to config string' % k)
        config_string_to_write += (';\n')
        config_string_to_write += ('; ' + options_sample_dict[k]['help'] + '\n')
        config_string_to_write += (k + ' = ' + str(config[k]) + '\n')
    logger.debug('Config string to write:\n')
    logger.debug(config_string_to_write)
    logger.info('Writing config file at: %s\n' % my_config_file)
    with open(my_config_file, 'w') as cf:
        cf.write(config_string_to_write)

# What we get from configparser is a string. For
# probe_properties_to_report, we need convert this string to a list.
# (ast.literal_eval() is safer than plain eval())
probe_properties_to_report = ast.literal_eval(config['probe_properties_to_report'])

logger.debug('Config dict:')
for k, v in config.items():
    logger.debug('%s : %s' % (k, v))

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
        logger.debug(str(_possible_unixtime) + ' is not inbetween ' + str(oldest_result_unixtime) + ' and ' + str(current_unixtime) + '.\n')
        return False

##########
# Try a few formats to convert the datetime string they've supplied into unixtime
def user_datetime_to_valid_unixtime(user_dt_string):
    accepted_datetime_formats = [ '%Y%m%d', '%Y%m%d%H%M',
                                  '%Y%m%d_%H%M', '%Y%m%d_%H:%M',
                                  '%Y%m%d.%H%M', '%Y%m%d.%H:%M',
                                   '%Y%m%d %H%M', '%Y%m%d %H:%M',
                                  '%Y-%m-%d_%H%M', '%Y-%m-%d_%H:%M',
                                  '%Y-%m-%d-%H%M', '%Y-%m-%d-%H:%M']
    # First, check to see if what's supplied is a valid-looking integer
    # representation of a reasonable unix time (seconds since the
    # the 1 Jan 1970 Epoch)
    if is_valid_unixtime(user_dt_string):
        return int(user_dt_string)
    # It's not unix time, so try to convert from some data time formats
    for f in accepted_datetime_formats:
        try:
            # print (user_dt_string + ' / ' + f)
            _unixtime_candidate = int(time.mktime(time.strptime(user_dt_string, f)))
            if is_valid_unixtime(_unixtime_candidate):
                logger.debug('Accepted %i as valid unixtime.\n' % _unixtime_candidate)
                return (_unixtime_candidate)
        except ValueError:
            ...
    # If fall out the bottom of the (above) for loop, then we do not have a valid time
    logger.critical('Cannot validate "' + user_dt_string + '" as a date-time representation\n')
    exit(2)

# A list that might contain the user-supplied time period durations
# durations = [args[0].duration1, args[0].duration2 ]
# A list that might contain the unixtime representation of the user-supplied start times
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
if args[0].datetime1:
    logger.debug(args[0].datetime1)
    unixtimes[0] = user_datetime_to_valid_unixtime(args[0].datetime1)
if args[0].datetime2:
    logger.debug(args[0].datetime2)
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
    logger.critical('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
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
        logger.critical('Please supply no more than two date times instead of %d.\n' % len(unixtimes))
        exit(3)
# They supplied two data sources:
elif len(data_sources) == 2:
    last_results_set_id = 1
#
#  They supplied something other than one or two data sources, which this script is not written to process.
else:
    logger.critical('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
    exit(3)


####################
#
# Process the data, either from a local file or by requesting it over the
# 'net from RIPE Atlas.
#
def process_request(_data_source, _results_set_id, _unixtime):
    logger.info('Trying to access data_source %s for unixtime %s\n' % (_data_source, _unixtime))
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
            logger.critical('This script does not yet know how to read user-supplied time ranges out of local files.\n (But it can query the RIPE Atlas API for time ranges, so maybe you wanna do that instead?\n')
    except:
        logger.debug('cannot read from file: %s\n' % _data_source)
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
                logger.info('Fetching latest results for Measurement %i from RIPE Atlas API...\n' % measurement_id)
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
                logger.info('Fetching results for Measurement %i,  start unixtime: %s  stop unixtime: %s\n' % (measurement_id, _unixtime, _stop_time))
                is_success, results = AtlasResultsRequest(**kwargs).create()
            if not is_success:
                logger.critical('Request of ' + _data_source + 'from RIPE Atlas failed.\n')
                exit(11)
        else:
            logger.critical('Cannot read from ' + _data_source + ' and it does look like a RIPE Atlas Measurement ID\n')
            sys.exit(12)

    # Variables that start with a m_ are specific to measurements.
    # All of the m_* dictionaries are initialized at the top of the script.
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
    # The list of seen probe IDs for this measurement-result-set
    m_seen_probe_ids[_results_set_id] = []
    m_probe_ids_to_exclude = []

    if args[0].exclusion_list_file:
        try:
            with open(args[0].exclusion_list_file, 'r') as f:
                m_probe_ids_to_exclude = f.read().splitlines()
        except IOError:
            logger.critical ('Cannot read probe exclusion list from file: %s\n' % args[0].exclusion_list_file)
            exit(13)

    # Loop through each (probe) result that come back from the call to DnsResult.
    for r in results:
        # this next line parses the data in r:
        dns_result = DnsResult(r, on_malformation=DnsResult.ACTION_IGNORE,
                               on_error=DnsResult.ACTION_IGNORE)
        # TODO: It's important to note that
        # 'on_error=DnsResult.ACTION_IGNORE' causes DnsResult to discard
        # std.err -- this script should be updated to catch and report
        # what's logged there.

        # Probe exclusion list handling, doing it here as to do it as
        # close to the source as possible. That is, as soon as we know
        # the ID's of the probes, we exclude those we don't want.
        if str(dns_result.probe_id) in m_probe_ids_to_exclude:
            continue

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
            #
            # first check if there is even a dns_result.responses[0].abuf,
            # because apparently sometimes there's not! :S (It seems like
            # if there is not an abuf, we might want to skip some of the
            # following code, but determining which lines can be skipped
            # adds complexity to this bug fix, so johan is not going to do
            # that right now.)
            if dns_result.responses[0].abuf:
                logger.debug('dns_result.responses[0].abuf: %s\n' % (dns_result.responses[0].abuf))
                if dns_result.responses[0].abuf.is_malformed:
                    m_total_abuf_malformeds[_results_set_id] += 1
            #            try dns_result.responses[1].get:
            if len(dns_result.responses) > 1: ### FIXME: Should this be 0 instead of 1?
                if dns_result.responses[1].abuf:
                    if dns_result.responses[1].abuf.is_malformed:
                        m_total_abuf_malformeds[_results_set_id] += 1
            # Appended results to the dicts...
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
                    logger.debug('%s\n' % (dns_server_fqdn))
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
    logger.debug(dir(measurement))
    m_ip_version[_results_set_id] = int(measurement.protocol)
    logger.debug("Address family for measurement %i is %i\n" % (measurement_id, m_ip_version[_results_set_id]))

    # Sort some of the lists of results
    m_response_times[_results_set_id].sort()
    m_timestamps[_results_set_id].sort()
    m_seen_probe_ids[_results_set_id].sort()
    logger.debug('m_seen_probe_ids[_results_set_id] is %d\n' % len(m_seen_probe_ids[_results_set_id]))
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
# RIPE Atlas API, and that can be a slow, latency-ful process.
#
# B) Why are there two cache files?
#
# RIPE publishes a (daily?) updated version of all the probe data in one
# bz2-compressed file via HTTPS or FTP, so we can download that
# periodically.  The probe info is formatted as a 1-line JSON blob, that
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
        logger.info('Reading in existing local JSON cache file %s...\n' % ppcf)
        with open(ppcf, 'r') as f:
            all_probes_dict = json.load(f)
    except:
        # The cache file does not seem to exist, so set the age to
        # zero, to trigger rebuild.
        logger.info('Local JSON cache file %s does not exist; generating it.\n' % ppcf)
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
            logger.info ('%s is out of date, so trying to fetch fresh probe data from RIPE...\n' % pprf)
            urlretrievefilename, headers = urllib.request.urlretrieve(ppurl, filename=pprf)
            html = open(pprf)
            html.close()
        except:
            logger.critical('Cannot urlretrieve %s -- continuing without updating %s \n' %
             (ppurl, pprf))
            os.replace(pprf + '.old', pprf)
            return(2)

    # If the raw file is newer than the local JSON cache file, decompress
    # and read it in on top of the probe properties cache dictionary.
    if ppcf_age < pprf_age:
        try:
            all_probes_list = json.loads(bz2.BZ2File(pprf).read().decode()).get('objects')
        except:
            logger.critical ('Cannot read raw probe data from file: %s\n' % pprf)
            return(1)
            # What we end up with in all_probes_list is a python list, but a
            # dictionary would be much more efficient keyed on the probe id would
            # be much more efficient, so we're going to burn some electricity and
            # convert the list into a dictionary.
        logger.info ('Converting the RIPE Atlas probe data into a dictionary and indexing it...\n')
        while len(all_probes_list) > 0:
            probe_info = all_probes_list.pop()
            probe_id = str(probe_info['id'])
            all_probes_dict[probe_id] = probe_info
            logger.debug('Seen probe IDs: ')
            logger.debug(all_probes_dict.keys())
        # now save that dictionary as a JSON file...
        logger.info ('Saving the probe data dictionary as a JSON file at %s...\n' % ppcf)
        with open(ppcf, 'w') as f:
            json.dump(all_probes_dict, f)
    logger.info('%s does not need to be updated.\n' % pprf)
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
    logger.info ('Reading the probe data dictionary as a JSON file from %s...\n' % ppcf)
    try:
        with open(ppcf, 'r') as f:
            all_probes_dict = json.load(f)
    except:
        logger.critical ('Cannot read probe data from file: %s\n' % ppcf)
        exit(13)
    # Loop through the list of supplied (seen) probe ids and collect their
    # info/meta data from either our local file or the RIPE Atlas API
    logger.info ('Matching seen probes with probe data; will query RIPE Atlas API for probe info not in local cache...\n')
    for p in probe_ids:
        if p in all_probes_dict.keys():
            probe_cache_hits += 1
            logger.debug('Probe %s info found in local cache.' % p)
            matched_probe_info[p] = all_probes_dict[p]
        else:
            # If it's not in the cache file, request it from RIPE
            #logger.debug ('NOT cached, trying RIPE Atlas...')
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
                logger.debug('Probe %9s info fetched from RIPE' % p)
            except:
                # Otherwise, it's empty
                # we did not find any information about the probe, so set values to '-'
                matched_probe_info[p] = { 'asn_v4': '-',
                                          'asn_v6': '-',
                                          'country_code': '-',
                                          'address_v4': '-',
                                          'address_v6': '-' }
                logger.debug('Failed to get info about probe ID %s in the local cache or from RIPE Atlas API.' % p)
    logger.info('cache hits: %i   cache misses: %i.\n' % (probe_cache_hits, probe_cache_misses))
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
    # m will receive the measurement ID for the processed data source
    logger.debug('data_source: %s  results_set_id: %i  unixtime: %i\n' % (data_sources[results_set_id], results_set_id, unixtimes[results_set_id]))
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
    logger.debug('Seen probe IDs set 0: ')
    logger.debug(m_seen_probe_ids_set[0])
    logger.debug('\nSeen probe IDs set 1: ')
    logger.debug(m_seen_probe_ids_set[1])
    if m_seen_probe_ids_set[0].isdisjoint(m_seen_probe_ids_set[1]):
        logger.critical('The two sets of measurement results do not have any probes in common.')
        logger.critical('Set 0: ')
        logger.critical(m_seen_probe_ids_set[0])
        logger.critical('\nSet 1: ')
        logger.critical(m_seen_probe_ids_set[1])
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
        logger.critical('WARNING: Measurements %i and %i were made for two different address families: %i vs. %i.\n  Only v4 probe info (ASN, IP address) will be displayed.\n'
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
        logger.critical('Unexpected result when updating local cache files: %s' % _res)
    p_probe_properties = load_probe_properties(probe_ids_to_list,
                                       config['ripe_atlas_probe_properties_json_cache_file'])
    header_label = [None, None]
    # Set the header labels based on what we're comparing (msm_ids or dates)
    #  If there are two dates, we want those as the header labels
    if args[0].datetime2 != None:
        logger.debug('hasattr datetime2')
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
    # Figure out how wide the text field should be for the IP address,
    #  depending upon the IP version.
    if report_ip_version == 4:
        address_width = 15
    elif report_ip_version == 6:
        address_width = 39
    else:
        logger.critical('Do not know what to set address width for IP version %i.' % report_ip_version)
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
            logger.critical('Unknown probe parameter: %s' % pp)
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
    # Iterate over the list of probe ids to list, then print out the
    # results per result set.
    probe_ids_to_list.sort()
    logger.debug('Probes to list: ' + str(probe_ids_to_list))
    logger.debug('Probes detail line format string: ' + probe_detail_line_format_string)
    for probe_id in probe_ids_to_list:
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
                rt_diff_fmt_chars = ''
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
            try:
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
            except:
                logger.debug("There is something unexpected in this probe info: ")
                for a in (probe_id,
                          str(p_probe_properties[probe_id]['display_asn']),
                          p_probe_properties[probe_id]['country_code'],
                          p_probe_properties[probe_id]['display_address'],
                          rt_a_fmt_chars,
                          rt_a,
                          rt_b_fmt_chars,
                          rt_b,
                          rt_diff_fmt_chars,
                          rt_diff,
                          rt_emph_char,
                          sites_fmt_chars,
                          sites_string,
                          sites_emph_char,
                          format_clear):
                    logger.debug(' ' + str(a))

