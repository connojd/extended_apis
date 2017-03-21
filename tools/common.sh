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

cat_rdmsr="0x4000"
    trap_rdmsr_access="0x1"
    trap_all_rdmsr_access="0x2"
    pass_rdmsr_access="0x3"
    pass_all_rdmsr_access="0x4"

cat_wrmsr="0x5000"
    trap_wrmsr_access="0x1"
    trap_all_wrmsr_access="0x2"
    pass_wrmsr_access="0x3"
    pass_all_wrmsr_access="0x4"

cat_rdrand="0x6000"
    trap_rdrand="0x1"
    pass_through_rdrand="0x2"

cat_rdseed="0x7000"
    trap_rdseed="0x1"
    pass_through_rdseed="0x2"

cat_wbinvd="0x8000"
    trap_wbinvd="0x1"
    pass_through_wbinvd="0x2"

cat_rdpmc="0x9000"
    trap_rdpmc="0x1"
    pass_through_rdpmc="0x2"

cat_rdtsc="0xA000"
    trap_rdtsc="0x1"
    pass_through_rdtsc="0x2"

cat_invlpg="0xB000"
    trap_invlpg="0x1"
    pass_through_invlpg="0x2"

cat_desc_table="0xC000"
    trap_desc_table="0x1"
    pass_through_desc_table="0x2"

cat_cr3_store="0xD000"
    trap_cr3_store="0x1"
    pass_through_cr3_store="0x2"

cat_cr3_load="0xE000"
    trap_cr3_load="0x1"
    pass_through_cr3_load="0x2"

cat_cr8_store="0xF000"
    trap_cr8_store="0x1"
    pass_through_cr8_store="0x2"

cat_cr8_load="0x10000"
    trap_cr8_load="0x1"
    pass_through_cr8_load="0x2"

cat_ept="0x20000"
    ept_on="0x1"
    ept_off="0x2"
    ept_trap_gva="0x3"
    ept_trap_gpa="0x4"
    ept_pass_through_gva="0x5"
    ept_pass_through_gpa="0x6"

cat_mov_dr="0x30000"
    trap_mov_dr="0x1"
    pass_through_mov_dr="0x2"

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
    if [[ $DBG -eq 1 ]]; then
        echo -e ""$CG"debug:"$CE" cat fun: $2"
        echo -e ""$CG"debug:"$CE" cpuid: $1"
    fi

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
