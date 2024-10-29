# ripe-atlas-dns-tools

A Python script to read and display RIPE Atlas measurement results for 
DNS measurements. There are three ingestion/reporting styles:

 - compare two separate Atlas measurement tests against each other, either
   as one-off tests, or picking a time/date for each.
 - compare a single multi-interval Atlas measurement against itself
   between two different times.
 - extract data for a specific moment in time (default: "now") and report
   latency

The primary goal is to evaluate the latency changes between the two 
measurements and allow quick visualizations in ASCII form that highlights
large changes. Additionally, differences in reported POP code (using NSID
results from DNS queries) are also output, allowing for A:B testing
examination for BGP changes on an anycast network. (note: format of NSID 
is currently assumed to be in Quad9 format of <hostname>.<POPcode>.suffix1.suffix2.tld)


## Dependencies

Python v3.6 (or later) and pip

...and also a few RIPE Atlas python packages (and their dependencies) that
will be installed via ```make install```, as described below.

## Installation steps:

* In the Makefile, review these variables and set them to what's
   sensible for your system:

```
PYTHON3
INSTALL_DIR
PYTHON_VENV_DIRPYTHON3
PIP
```

...**or**, you can override them on the command line like:

 ```make install PYTHON3=/usr/local/bin/python```

* If you've installed it before from this same source, you might want to
tidy up first,  mainly to regenerate ra-dns-check.sh, like so:
 ```make clean```

* Install the scripts:
 ```make install```

...then, you must do at least one of these steps for at least the first install:

* ```make venv```
* ```make install-pydeps```


After the initial install of the venv or python dependencies, you probably
don't need to do these again, unless the dependencies have changed.

## Additional feature

 * Added a --scrape argument. This argument will use the time provided (dtime1) variable to obtain the
  'rt' of DNS query. The output are formatted to allow Prometheus to scrape.
 * Additonally, another arugment --probes '<list of probes>' only output the specific probes values offered
  by the <list of probes>
 * if --datetime1 is missing, the latest set of data base on time now() will be output
```
ra-dns-check.py --datetime1 202210080000 12016241 --scrape
ra-dns-check.py --datetime1 202210080000 12016241 --scrape --probes "999,99" 
ra-dns-check.py 64573001 --scrape
```
 * Add autocomplete support via argcomplete module. This feature allows the usage of tab key for command/arguments completion.
```
pip install -r requirements.txt 
ra-dns-check.py --scrape 43869257 --autocomplete 
source <(register-python-argcomplete ra-dns-check.py)
```
* Enforce staleness of data under the Prometheus scrape feature. Staleness is defined period of the data that would be scraped between now() and the staleness period (in seconds). Stale data will be log as log level info.
```
# this command pull the latest data on Oct 8 2022 for measurement 38588031 (probe 928 abd 975)
ra-dns-check.py --datetime1 202210080000 12016241 --scrape --scrape_staleness_seconds 38588031 --probes "928,975" --log_level INFO
```

Originally written by Johan A. van Zanten for Quad9, with subsequent improvements by Quad9.
