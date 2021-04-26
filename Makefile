#
# Makefile for sysadmin tasks associated with johan's ripe-atlas-dns-tools

PYTHON3 = /opt/local/bin/python3.8
INSTALL_DIR = ${HOME}/ripe-atlas-dns-tool
PYTHON_VENV_DIR = ${INSTALL_DIR}/py-venv

ra-dns-check.sh: ra-dns-check.sh.template
	sed "s?__INSTALL_DIR__?$(INSTALL_DIR)? ; s?__PYTHON_VENV_DIR__?$(PYTHON_VENV_DIR)?" $? > ra-dns-check.sh


install: ra-dns-check.py ra-dns-check.sh
	-mkdir $(INSTALL_DIR)
	install -m 555 ra-dns-check.py ra-dns-check.sh $(INSTALL_DIR)

venv: requirements.txt
	./python-venv-create.sh $(PYTHON3) $(PYTHON_VENV_DIR)

clean:
	rm ra-dns-check.sh

wipe-venv:
	rm -fr $(INSTALL_DIR)
