#!/bin/bash -e
#
# Bareflank Extended APIs
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# ------------------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------------------

CB='\033[1;35m'
CC='\033[1;36m'
CY='\033[1;33m'
CG='\033[1;32m'
CR='\033[1;31m'
CE='\033[0m'

# ------------------------------------------------------------------------------
# Environment
# ------------------------------------------------------------------------------

NUM_CORES=`grep -c ^processor /proc/cpuinfo`

# ------------------------------------------------------------------------------
# vmcall categories and their functions (see eapis exit handler vmcall_interface.h)
# ------------------------------------------------------------------------------
cat_io="0x1000"
    trap_io_access="0x3"
    trap_all_io_access="0x4"
    pass_io_access="0x5"
    pass_all_io_access="0x6"

cat_vpid="0x2000"
    vpid_on="0x1"
    vpid_off="0x2"

cat_msr="0x3000"

cat_rdmsr="0x4000"

cat_wrmsr="0x5000"


cat_util="0x100"
    verbose_on="0x1"
    verbose_off="0x2"

cat_rdrand="0x200"
    rdrand_trap="0x1"
    rdrand_pass_through="0x2"

cat_rdseed="0x300"
    rdseed_trap="0x1"
    rdseed_pass_through="0x2"

cat_wbinvd="0x400"
    wbinvd_trap="0x1"
    wbinvd_pass_through="0x2"

# eapis_cat
r2=""

# eapis_fun
r3=""

# arg to eapis_fun
r4=""

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

header() {
    echo "----------------------------------------"
    echo $1
}

footer() {
    echo ""
}

vmcall_select_core() {
    echo "register args = $2"
    echo "cpuid = $1"

    ARGS="--cpuid $1 registers $2" make vmcall > /dev/null
}

config_all_cores() {
    for (( core=0; core<$NUM_CORES; core++ ))
    do
        vmcall_select_core $core "$1"
    done
}

config_select_cores() {

    args="$1"
    ncores="$2"

    echo "args: $args"
    echo "ncores: $ncores"

    shift 2

    for (( i=1; i<="$ncores"; i++ ))
    do
        if (( "$1">=0 && "$1"<NUM_CORES )); then
            vmcall_select_core "$1" "$args"
        else
            echo -e ""$CR"error"$CE": $1 is not a valid core number"
            echo -e ""$CR"error"$CE": ensure 0 =< core number < NUM_CORES"
            exit 22
        fi
        shift
    done
}
