#!/bin/bash

#
# Configuration Example - MSR
#

source $HOME/hypervisor/extended_apis/tools/common.sh

if [[ -f $HOME/hypervisor/vmconfig ]]; then
    vmconfig=$HOME/hypervisor/vmconfig
else
    echo -e ""$CR"error"$CE": vmconfig file not found"
    exit 2
fi

# Configure all cores to trap on all RDMSR access
$vmconfig rdmsr -f t -r all -c all

# Configure core 0 and 1 to trap on WRMSR to 0x10
$vmconfig wrmsr -f t -r 0x10 -c 0 1

# Configure all cores to pass-through all MSR access
$vmconfig rdmsr -f p -r all -c all
$vmconfig wrmsr -f pass -r all -c all
