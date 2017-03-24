#!/bin/bash

#
# Configuration Example - RDRAND/RDSEED
#

# Configure core 0 to trap on RDSEED and RDRAND
./vmconfig rdrand -f t -c 0
./vmconfig rdseed -f t -c 0

# Configure all cores to trap on RDSEED
./vmconfig rdseed -f t -c all

# Configure all cores to pass-through RDSEED and RDRAND
./vmconfig rdseed -f p -c all
./vmconfig rdrand -f p -c all
