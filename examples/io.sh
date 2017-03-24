#!/bin/bash

#
# Configuration Example - IO
#

# Configure all cores to trap on all IO access
./vmconfig io -f t -p all -c all

# Configure core 0 to pass-through IO access to 0xCF3
./vmconfig io -f pass -p 0xcf3 -c 0

# Configure all cores to pass-through all IO access
./vmconfig io -f p -p all -c all
