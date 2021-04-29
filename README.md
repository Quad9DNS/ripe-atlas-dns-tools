# ripe-atlas-dns-tools

A Python script to read and display RIPE Atlas DNS Measurement results

## Dependencies

Python v3.6 or later
pip

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

...then, you must do one these steps for at least the first install :

* ```make venv```   **OR**   ```make install-pydeps```
