#!/bin/bash

#
# Configuration Example - EPT
#

# Enable EPT
./vmconfig ept -f on

# Trap on guest physical addresses 0x1000 and 0x5004
./vmconfig ept -f t -a 0x1000
./vmconfig ept -f t -a 0x5004

# Pass through those addresses
./vmconfig ept -f p -a 0x1000
./vmconfig ept -f p -a 0x5004

# Disable EPT
./vmconfig ept -f off
