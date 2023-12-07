# ripe-atlas-dns-tools

A Python script to read and display RIPE Atlas DNS Measurement results

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
* ```ra-dns-check.py --datetime1 202210080000 12016241 --scrape```  
* ```ra-dns-check.py --datetime1 202210080000 12016241 --scrape --probes "999,99"```  
