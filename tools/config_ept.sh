#!/bin/bash

ept_usage() {
    printf ""$CC"usage 1"$CE": ./vmconfig ept -f on | off (turn EPT on/off for all cores)\n"
    printf ""$CC"usage 2"$CE": ./vmconfig ept -f <fun> -a <gpa> -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <gpa> = 0x<guest phys addr to configure>"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
    echo -e ""$CG"note"$CE": EPT is enabled globally so each core shares the same"
    echo -e ""$CG"note"$CE": EPT paging structure.  The default amount of physical"
    echo -e ""$CG"note"$CE": memory mapped is 64GB.  You may trap on up to 256"
    echo -e ""$CG"note"$CE": different 4k pages at a time. These parameters are found"
    echo -e ""$CG"note"$CE": in extended_apis/include/vmcs/vmcs_intel_x64_eapis.h and"
    echo -e ""$CG"note"$CE": can, in theory, be tweaked."
}

all_cores=0

set_ept_func() {

    r2=$cat_ept
    fun=$1

    case "$fun" in
    "on")
        r3=$ept_on
        all_cores=1
        ;;
    "off")
        r3=$ept_off
        all_cores=1
        ;;
    "t"|"trap")
        if [[ "$2" = "-a" ]]; then
            r3=$ept_trap_gpa
            r4=$3
        else
            echo -e ""$CR"error"$CE": invalid ept syntax"
            ept_usage
            exit 22
        fi
        ;;
    "p"|"pass")
        if [[ "$2" = "-a" ]]; then
            r3=$ept_pass_through_gpa
            r4=$3
        else
            echo -e ""$CR"error"$CE": invalid ept syntax"
            ept_usage
            exit 22
        fi
        ;;
    *)
        echo -e ""$CR"error"$CE": invalid ept syntax"
        ept_usage
        exit 22
    esac
}

config_ept() {

    if [[ "$2" = "-f" ]]; then
        set_ept_func $3 $4 $5
    else
        echo -e ""$CR"error"$CE": invalid ept syntax"
        ept_usage
        exit 22
    fi

    if [[ $all_cores -eq 1 ]]; then
        config_all_cores "$r2 $r3"
        exit 0
    fi

    while [[ "$1" != "-c" ]]; do
        shift 1
    done

    if [[ $# -eq 0 ]]; then
        echo -e ""$CR"error"$CE": invalid ept syntax: no cores listed"
        ept_usage
        exit 22
    fi

    if [[ "$2" = "all" ]]; then
            config_all_cores "$r2 $r3 $r4"
            exit 0
    fi

    shift 1
    ncores=$#
    cores="$@"

    config_select_cores "$r2 $r3 $r4" $ncores $cores
}
