# ripe-atlas-dns-tools

A Python script to read and display RIPE Atlas measurement results for 
DNS measurements. There are two ingestion styles:

 - compare two separate Atlas measurement tests against each other, either
   as one-off tests, or picking a time/date for each.
 - compare a single multi-interval Atlas measurement against itself
   between two different times.

The primary goal is to evaluate the latency changes between the two 
measurements and allow quick visualizations in ASCII form that highlights
large changes.  Additionally, differences in reported POP code (using NSID
results from DNS queries) are also output, allowing for A:B testing
examination for BGP changes on an anycast network. (note: format of NSID 
is currently assumed to be in Quad9 format of hostname.POPcode.suffix1.suffix2.tld)


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
