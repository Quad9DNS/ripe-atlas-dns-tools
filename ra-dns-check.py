#!/usr/bin/env python3
#

# v2.0

# ra-dns-check.py
#
# Parse, summarize, sort, and display measurement results for DNS queries
# made by RIPE Atlas probes

# Please see the file LICENSE for the license.

import argparse
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
#
# There are some defaults defined in the "sample_config" string below, but
# you should edit them in the config file instead of bellow.
# (If the config file does not exist, this script creates it from this string.)
#
# Options specified in the command line can then also be overridden by what's specified on the command line.
#
sample_config = """# Config file for ra-dns-check.py
# Some important synxax notes:
#
# 1) This file is read by the ConfigParser python module, and (perhaps
#    surprisingly) that means it expects INI syntax *NOT* python syntax. So:
#    * do NOT enclose strings within quotes or double quotes
#    * protect (escape) any % character with another %
#    * use either : or = to separate a config variable (key) and its value.
#    * spaces are allowed *within* (as part of) a value or key!
#
# 2) Please do not remove or change the next line ("[DEFAULT]"), as python's ConfigParser module needs it.
[DEFAULT]
#
# Wikipedia says 2010 was when RIPE Atlas was established, so we use that
# as a starting point for when it might contain some data.
oldest_atlas_result_datetime = 2010 01 01 00:00:00
#
# There are a couple of files used to locally cache probe data, the first comes directly from RIPE:
ripe_atlas_probe_properties_raw_file = """ + os.environ['HOME'] + '/.RIPE_atlas_all_probe_properties.bz2' + """
# the second cache file we generate, based upon probe info we request (one at a time) from the RIPE Atlas API.
ripe_atlas_probe_properties_json_cache_file = """ + os.environ['HOME'] + '/.RIPE_atlas_probe_properties_cache_file.json' + """
# The max age of the RIPE Atlas probe info file. (older than this and we download a new one)
raw_probe_properties_file_max_age = 86400
# where to fetch the RA probe properties file
ripe_atlas_current_probe_properties_url = https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest
# The ordered list of properties to display in the (default) detailed listing per probe.
probe_properties_to_report = ['probe_id', 'asn', 'country_code',
                               'ip_address', 'rt_a', 'rt_b', 'rt_delta', 'dns_response']
"""
#
####################
#
# Config file
#
all_config = configparser.ConfigParser()
try:
    if os.stat(my_config_file):
        if os.access(my_config_file, os.R_OK):
            ### sys.stderr.write('Found config file at %s; reading it now...\n' % my_config_file)
            all_config.read(my_config_file)
        else:
            sys.stderr.write('Config file exists at %s, but is not readable.\n' % my_config_file)
except FileNotFoundError:
    ### sys.stderr.write('Config file does not exist at %s; creating new one...\n' % my_config_file)
    all_config.read_string(sample_config)
    with open(my_config_file, 'w') as cf:
        cf.write(sample_config)

#
# FIXME ... the problem is all the config tuples are strings, and now we need to convert them back.
config = all_config['DEFAULT']
#
# Loop through what's in the config and see if each variable is in the
# following list of expected config variables to catch any unexpected
# ("illegal") parameters in the config file, rather than let a typo or
# some bit of random (non-comment) text in the config file go unnoticed.
expected_config_items =['oldest_atlas_result_datetime',
                 'ripe_atlas_probe_properties_json_cache_file',
                 'ripe_atlas_probe_properties_raw_file',
                 'raw_probe_properties_file_max_age',
                 'ripe_atlas_current_probe_properties_url',
                 'probe_properties_to_report']
for item in config:
    if item not in expected_config_items:
        sys.stderr.write('Unknown parameter in config file: %s\n' % item)
        exit(1)
    ### else:
    ###    sys.stderr.write('%s : %s\n' % (item, config[item]))
###exit()

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
parser.add_argument('--datetime1', '--dt1', help='date-time to start 10-minute period for FIRST set of results (UTC). Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")', type=str)
parser.add_argument('--datetime2', '--dt2', help='date-time to start 10-minute period for SECOND set of results (UTC) Format: 1970-01-01_0000 OR the number of seconds since then (AKA "Unix time")', type=str)
parser.add_argument('-a', '--all_probes', help='show information for probes presnt in *either* result sets, not just those present in *both* sets', action='store_true', default=False)
parser.add_argument('-c', '--color', '--colour', help='colorize output', action="store_true", default=True)
parser.add_argument('-C', '--no_color', '--no_colour', help='do NOT colorized output (AKA "colourised output")', action="store_true")
parser.add_argument('-e', '--emphasis_chars', help='add a trailing char (! or *) to abberant sites and response times', action="store_true")
parser.add_argument('-H', '--no_header', help='Do NOT show the header above the probe list', action="store_true")
parser.add_argument('-i', '--item_occurence_to_return', help='Which item to return from the split-list. First element is 0.', type=int, default='1')
parser.add_argument('-l', '--latency_diff_threshold', help='the amount of time difference (ms) that is significant when comparing latencies bewtween tests', type=int, default=5)
parser.add_argument('-P', '--donotlistprobes', help='do NOT list the results for each probe', action='store_true')
parser.add_argument('-s', '--list_slow_probes_only', help='in per-probe list, show ONLY the probes reporting response times', action='store_true')
parser.add_argument('-S', '--slow_threshold', help='override the default slow response threshold', default=50, type=int)
parser.add_argument('-t', '--split_char', help='character (delimiter) to split the string on (can occur in the string more than once.', type=str, default='.')
parser.add_argument('-u', '--summarystats', help='show summary stats', action='store_true')
parser.add_argument('filename_or_msmid', help='one or two local filenames or RIPE Atlas Measurement IDs', nargs='+')
parser.format_help()
args = parser.parse_known_args()
### print (args[0]) ### debug
### print (args[0].split_char) ### debug
### exit()

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
    accepted_datetime_formats = [ '%Y%m%d%H%M', '%Y%m%d_%H%M', '%Y%m%d_%H:%M',
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

# We're expecting to process one or two sets of results for comparison.  Often,
# we're comparing two different measurement ids, but it's also possible to
# compare multiple sets of data called for the measurement id, so we
# create a results set id to organize and index the sets of results, instead of using
# the measurement id.
results_set_id = 0

# m_ are variables specific to measurement-sets
# p_ are variables specific to probes
# pm_ are variables specific to probe, per each measurement
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
measurement_ids = []

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
if args[0].datetime1 != None:
    unixtimes[0] = user_datetime_to_valid_unixtime(args[0].datetime1)
if args[0].datetime2 != None:
    unixtimes[1] = user_datetime_to_valid_unixtime(args[0].datetime2)

# Because this script is written to compare two measurement results, or
# just report one, this is kinda complicated:
# Set our last results set id
# to the length of the data_sources list.  (It should be either 0 or 1,
# but maybe this script will be modified to compare more than two sets of
# data, so try not to block that...)  last_results_sets_id =

# The args parsing setup should prevent this from happening, but just in case...
if len(data_sources) == 0:
    sys.stderr.write('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
    exit(3)
# They've supplied one msm or file...
elif len(data_sources) == 1:
    # ...so see how many timedates they supplied...
    if (unixtimes[0] + unixtimes[1]) < 2:
        # We have one data source and only one time...
        last_results_set_id = 0
    # We have one data source and two times...
    else:
        # We set the second data source to be the same as the first,
        # otherwise the main loop would need logic to handle it being unset.
        data_sources.append(data_sources[0])
        last_results_set_id = 1
# They supplied two data sources:
elif len(data_sources) == 2:
    last_results_set_id = 1
#  They supplied something other than one or two data sources, which this script is not written to process.
else:
    sys.stderr.write('Please supply one or two local filenames or RIPE Atlas Measurement IDs.\n')
    exit(3)


####################
#
# Process the data, either from a local file or by requesting it over the
# 'net from RIPE Atlas.
#
def process_request(data_source, results_set_id, _unixtime):
    ### sys.stderr.write('Trying to access: %s\n' % data_source)
    # First we try to open the data_source as a local file.  If it exists,
    # read in the measurement results from a filename the user has
    # supplied.
    #
    # This code currently reads everything in, but it should be
    # modified to only load the data from the user-supplied time range,
    # if the user supplied one.
    try:
        f = open(data_source, "r")
        results = json.load(f)
        f.close()
        if _unixtime != 0:
            sys.stderr.write('This script does not yet know how to read user-supplied time ranges out of local files.\n (But it can query the RIPE Atlas API for time ranges, so maybe you wanna do that instead?\n')
    except:
        ### sys.stderr.write('cannot read from file: %s\n' % data_source)
        # If we are here, accessing data_sources as a local file did not
        # work.  Next, we try to check to see if data_source is an 8-digit
        # number.  If it is, then we assume it is an Atlas Measurement ID
        # and query their API with it.
        if re.match(r'^[0-9]{8}$', data_source):
            # use it to make the request, but the measurement ID in the
            # returned data will be passed back to the code calling this
            # function, potentially redefining the measurement ID from
            # what the user supplied. (That really should not happen, but
            # the world is a weird place.)
            measurement_id = int(data_source)
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
                sys.stderr.write('Request of ' + data_source + 'from RIPE Atlas failed.\n')
                exit(11)
        else:
            sys.stderr.write('Cannot read from ' + data_source + ' and it does look like a RIPE Atlas Measurement ID\n')
            sys.exit(12)

    # Variables that start with a m_ are specific to measurements.
    # All of the m_* dictionaries are initalized at the top of the script.
    # Here, we are initializing the structure we will be writing into for this results_set_id.
    # (results set identifier)
    m_total_responses[results_set_id] = 0
    m_total_response_time[results_set_id] = 0
    m_total_malformeds[results_set_id] = 0
    m_total_abuf_malformeds[results_set_id] = 0
    m_total_errors[results_set_id] = 0
    m_total_slow[results_set_id] = 0
    m_response_time_average[results_set_id] = 0
    m_response_time_std_dev[results_set_id] = 0
    #
    m_response_times[results_set_id] = []
    m_timestamps[results_set_id] = []
    # The list of seen probe IDs for this measurentment-result-set
    m_seen_probe_ids[results_set_id] = []

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
        results_and_probes_id = str(results_set_id) + '-' + str(dns_result.probe_id)
        # Add the probe_id to the seen list.  We need to cast it to a
        # string, because the corresponding probe IDs in probe_info data
        # will be indexed by probe_id as a string.  (Because python.)
        m_seen_probe_ids[results_set_id].append(str(dns_result.probe_id))
        m_total_responses[results_set_id] += 1
        # Check for malformed responses or errors, and count them
        if dns_result.is_malformed:
            m_total_malformeds[results_set_id] += 1
        elif dns_result.is_error:
            m_total_errors[results_set_id] += 1
        else:
            # Even more (abuf) error checks...
            if dns_result.responses[0].abuf.is_malformed:
                m_total_abuf_malformeds[results_set_id] += 1
            #            try dns_result.responses[1].get:
            if len(dns_result.responses) > 1: ### FIXME: Should this be 0 instead of 1?
                if dns_result.responses[1].abuf.is_malformed:
                    m_total_abuf_malformeds[results_set_id] += 1
            # ... otherwise appended results to the dicts...
            m_response_times[results_set_id].append(dns_result.responses[0].response_time)
            m_total_response_time[results_set_id] += (dns_result.responses[0].response_time)
            if dns_result.responses[0].response_time > args[0].slow_threshold:
                m_total_slow[results_set_id] += 1
            m_timestamps[results_set_id].append(dns_result.created_timestamp)
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
                    if len(split_result) > args[0].item_occurence_to_return:
                        pm_dns_server_substring[results_and_probes_id] = split_result[args[0].item_occurence_to_return]
                    else:
                        pm_dns_server_substring[results_and_probes_id] = dns_server_fqdn
            except IndexError:
                pm_dns_server_substring[results_and_probes_id] = 'no_reply'
            except AttributeError:
                pm_dns_server_substring[results_and_probes_id] = 'no_data'

    # Sort some of the lists of results
    m_response_times[results_set_id].sort()
    m_timestamps[results_set_id].sort()
    m_seen_probe_ids[results_set_id].sort()
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
                # we did not find any information about the prove, so set values to empty
                matched_probe_info[p] = { 'asn_v4': None,
                                          'country_code': None,
                                          'address_v4': None }
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
    if args[0].summarystats:
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

# Check to see if there are two sets of results
if last_results_set_id > 0:
# ... if there are, see if there are probes common to the two sets
# -- if there are not, exit
    ### print (m_seen_probe_ids_set[0])
    ### print (m_seen_probe_ids_set[1])
    if m_seen_probe_ids_set[0].isdisjoint(m_seen_probe_ids_set[1]):
        sys.stderr.write('The two sets of measurement results do not have any probes in common.\n')
        sys.stderr.write('Set 0')
        for p in m_seen_probe_ids_set[0]:
            sys.stderr.write(p)
        sys.stderr.write('\nSet 1')
        for p in m_seen_probe_ids_set[1]:
            sys.stderr.write(p)
        sys.stderr.write('\n')
        exit(14)
    # if there are probes in common, build a uniq set of all probe ids
    # seen in both sets of measurements, and a list of common probe IDs
    else:
        common_probe_ids = list(m_seen_probe_ids_set[0].intersection(m_seen_probe_ids_set[1]))
        uniq_seen_probe_ids = list(m_seen_probe_ids_set[0].union(m_seen_probe_ids_set[1]))
# Only one set of results, so use its uniq set of the seen probe IDs.
else:
    uniq_seen_probe_ids = list(m_seen_probe_ids_set[0])
    common_probe_ids = uniq_seen_probe_ids

##################################################
#
# Printing output is complicated.
# If we are printing out detailed (per-probe) stats, we do what's below...
# From v1.1, by DEFAULT, we list each probe's properties!
if not args[0].donotlistprobes:
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
    #
    # Setting up and printing the header for the probes it's remarkably
    # complicated.
    ### print (measurement_ids)
    if not args[0].no_header:
        # Set the header labels based on what we're comparing (msm_ids or dates)
        header_label = [None, None]
        #  If there are two dates, we want those as the header labels
        if args[0].datetime2 != None:
            ### print ('hasattr datetime2')
            header_label[0] = args[0].datetime1
            header_label[1] = args[0].datetime2
        #  Otherwise, if there are two msm_ids, we want those as the header labels
        elif len(measurement_ids) == 2:
            header_label = measurement_ids
        # Last, we just use the one msm_id
        else:
            header_label[0] = measurement_ids[0]
        sys.stderr.write ('%12s %10s %4s %15s  %13s %13s %12s %15s\n' % ('Probe_ID', 'ASN', 'CC', 'IP_Address', str(header_label[0]) + '(ms)', str(header_label[1]) + '(ms)', 'diff(ms)', 'DNSSrvsubstr[:B]'))
        sys.stderr.write ('---------------------------------------------------------------------------------------------------\n')
    #
    # Iterate over the list of probe ids to lis, then print out the
    # results per result set.
    ### print (probe_ids_to_list)
    for probe_id in probe_ids_to_list:
        # get this (one) probe's properties
        #p_probe_properties[probe_id] = report_probe_properties(probe_id)
        #
        # Prepare what will be printed based on result set
        # generate an response_set + probe_id to use as an index into
        # various dicts with responses
        results_and_probes_id = str(0) + '-' + str(probe_id)
        next_results_and_probes_id = str(1) + '-' + str(probe_id)
        a = pm_response_time.setdefault(results_and_probes_id, -1)
        b = pm_response_time.setdefault(next_results_and_probes_id, -1)
        a_fmt_chars = fmt.clear
        b_fmt_chars = fmt.clear
        sites_fmt_chars = fmt.clear
        rt_emph_char = ''
        sites_emph_char = ''
        rt_fmt_chars = fmt.clear
        if a > 0 and b > 0:
            rt_diff = b - a
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
        if not args[0].list_slow_probes_only or (args[0].list_slow_probes_only and ((a > args[0].slow_threshold) or (b > args[0].slow_threshold))):
            if args[0].no_color:
                print ('%12s %10s %4s %15s %13.2f %13.2f %12.2f%s %15s%s' %
                       (probe_id, p_probe_properties[probe_id]['asn_v4'],
                        p_probe_properties[probe_id]['country_code'],
                        p_probe_properties[probe_id]['address_v4'], a, b, rt_diff,
                        rt_emph_char, sites_string, sites_emph_char))
            else:
                # Part 2 of the formatting...
                #
                # Slow sites are yellow, and non-responding sites (we
                # set to -1) get magenta
                if a > args[0].slow_threshold:
                    a_fmt_chars = fmt.bright_yellow
                elif a < 0:
                    a_fmt_chars = fmt.bright_magenta
                if b > args[0].slow_threshold:
                    b_fmt_chars = fmt.bright_yellow
                elif b < 0:
                    b_fmt_chars = fmt.bright_magenta
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
                    #
                    # finally done applying formating!
                    ### print (p_probe_properties[probe_id])
                print ('%12s %10s %4s %15s %s%13.2f %s%13.2f %s%12.2f%s %s%15s%s%s' %
                       (probe_id,
                        p_probe_properties[probe_id]['asn_v4'],
                        p_probe_properties[probe_id]['country_code'],
                        p_probe_properties[probe_id]['address_v4'], a_fmt_chars, a,
                        b_fmt_chars, b, rt_diff_fmt_chars, rt_diff,
                        rt_emph_char, sites_fmt_chars, sites_string,
                        sites_emph_char, fmt.clear))
