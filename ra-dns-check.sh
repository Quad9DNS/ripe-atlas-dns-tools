#!/bin/env bash

_D="/usr/local/atlas"

. $_D/ra-dns/bin/activate

$_D/ra-dns-check.py $@
