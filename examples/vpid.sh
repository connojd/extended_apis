#!/bin/bash

#
# Configuration Example - VPID
#

if [[ -f $HOME/hypervisor/vmconfig ]]; then
    vmconfig=$HOME/hypervisor/vmconfig
else
    echo -e ""$CR"error"$CE": vmconfig file not found"
    exit 2
fi

# Enable VPID on core 0 and 1
$vmconfig vpid -f on -c 0 1

# Disable VPID on all cores
$vmconfig vpid -f off -c all

