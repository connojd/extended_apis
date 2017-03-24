#!/bin/bash

#
# Configuration Example - IO
#

if [[ -f $HOME/hypervisor/vmconfig ]]; then
    vmconfig=$HOME/hypervisor/vmconfig
else
    echo -e ""$CR"error"$CE": vmconfig file not found"
    exit 2
fi

# Configure all cores to trap on all IO access
$vmconfig io -f t -p all -c all

# Configure core 0 to pass-through IO access to 0xCF3
$vmconfig io -f pass -p 0xcf3 -c 0

# Configure all cores to pass-through all IO access
$vmconfig io -f p -p all -c all
