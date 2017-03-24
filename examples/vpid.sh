#!/bin/bash

#
# Configuration Example - VPID
#

# Enable VPID on core 0 and 1
./vmconfig vpid -f on -c 0 1

# Disable VPID on all cores
./vmconfig vpid -f off -c all
