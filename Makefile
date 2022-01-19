#
# Makefile for sysadmin tasks associated with johan's ripe-atlas-dns-tools

# The RIPE Atlas packages required at least version 3.6 of python
PYTHON3 = python3

# The directory to install the scripts in
INSTALL_DIR = ${HOME}/ripe-atlas-dns-tool

# If you want a python venv, this is where it will be created:
PYTHON_VENV_DIR = ${INSTALL_DIR}/py-venv

# Sometimes this might need to be just "pip"
PIP = pip3

TEST_DATA_DIR = ./Test-Data

help:
	mdcat README.md || cat README.md

# A wrapper script to run the real ra-dns-check.py within a python venv
ra-dns-check.sh: ra-dns-check.sh.template
	sed "s?__INSTALL_DIR__?$(INSTALL_DIR)? ; s?__PYTHON_VENV_DIR__?$(PYTHON_VENV_DIR)?" $? > ra-dns-check.sh

# Dependencies that the script needs, including the RIPE Atlas pkgs.
install-pydeps:
	$(PIP) install -r requirements.txt ||	echo "If you saw an error about Rust and SSL, you might need to do: $(PIP) install --upgrade pip"

install: ra-dns-check.py
	mkdir -p $(INSTALL_DIR)
	install -m 555 ra-dns-check.py $(INSTALL_DIR)
	@echo " "
	@echo "ra-dns-check.py was installed in: $(INSTALL_DIR)/"
	@echo " "
	@echo "To install the python dependencies choose ONE of:"
	@echo " A) make venv -- then run ra-dns-check.sh which uses the python venv)"
	@echo " B) make install-pydeps -- no python venv, so you use ra-dns-check.py directly"

# Create a python venv
venv: requirements.txt ra-dns-check.sh
	mkdir -p $(INSTALL_DIR)
	install -m 555 ra-dns-check.sh $(INSTALL_DIR)
	./python-venv-create.sh $(PYTHON3) $(PYTHON_VENV_DIR)

# Cleanup stuff make generates locally
clean:
	rm ra-dns-check.sh

# Remove everything the python venv directory that was createrd with "make venv"
wipe-venv:
	rm -fr $(INSTALL_DIR)/py-venv

tests:
	./output_tests.sh -t $(TEST_DATA_DIR)

config-file:
	./ra-dns-check.py --config_file ./default_config_file \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29083406.json \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29096558.json >/dev/null 2>&1

benchmark:
	./output_tests.sh -t $(TEST_DATA_DIR)	-B

debug-info:
# ./ra-dns-check.py --log_level INFO --datetime1 20210101 --datetime2 20210301 12016241
	./ra-dns-check.py --log_level INFO \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29083406.json \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29096558.json

debug-debug:
	./ra-dns-check.py --log_level DEBUG \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29083406.json \
		$(TEST_DATA_DIR)/RIPE-Atlas-measurement-29096558.json
