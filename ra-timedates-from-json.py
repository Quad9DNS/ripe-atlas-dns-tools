#!/usr/bin/env python3

# print out the "normal" date/times from RIPE Atlas JSON data file

import json
import logging
import sys
import time

# Change "CRITICAL" to DEBUG if you want debugging-level logging *before* this
# script parses command line args, and subsequently sets the debug level:
#logging.basicConfig(level=logging.CRITICAL)
#logging.basicConfig(level=logging.DEBUG)

for f in sys.argv[1:]:
  json_blob = {}
  print(f)
  with open(f) as input_file:
  #  for line in input_file:
  #    json_line = json.loads(line)
    json_blob = json.load(input_file)
    for result in json_blob:
      print(time.strftime('%x %X' ,time.gmtime(result['timestamp'])))
