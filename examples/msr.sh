#!/bin/bash

#
# Configuration Example - MSR
#

# Configure all cores to trap on all RDMSR access
./vmconfig rdmsr -f t -r all -c all

# Configure core 0 and 1 to trap on WRMSR to 0x10
./vmconfig wrmsr -f t -r 0x10 -c 0 1

# Configure all cores to pass-through all MSR access
./vmconfig rdmsr -f p -r all -c all
./vmconfig wrmsr -f pass -r all -c all
