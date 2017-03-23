#!/bin/bash

source extended_apis/tools/common.sh

msr=""

msr_usage() {
    printf ""$CC"usage"$CE": ./vmconfig $1 -f <fun> -r <msr> -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <msr> = all | 0x<msr_addr>"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_msr_cat() {
    if [[ "$1" = "rdmsr" ]]; then
        r2=$cat_rdmsr
        trap_all_msr_access=$trap_all_rdmsr_access
        pass_all_msr_access=$pass_all_rdmsr_access
        trap_msr_access=$trap_rdmsr_access
        pass_msr_access=$pass_rdmsr_access

    elif [[ "$1" = "wrmsr" ]]; then
        r2=$cat_wrmsr
        trap_all_msr_access=$trap_all_wrmsr_access
        pass_all_msr_access=$pass_all_wrmsr_access
        trap_msr_access=$trap_wrmsr_access
        pass_msr_access=$pass_wrmsr_access
    fi
}

set_msr_func() {

    fun="$2"
    msr="$3"

    if [[ "$msr" = "all" ]]; then

        if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
            r3=$trap_all_msr_access
            return
        elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
            r3=$pass_all_msr_access
            return
        else
            echo -e ""$CR"error"$CE": invalid $1 function"
            msr_usage $1
            exit 22
        fi
    fi

    # assume msr conforms to syntax
    r4="$msr"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_msr_access
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_msr_access
        return
    else
        echo -e ""$CR"error"$CE": invalid $1 function"
        msr_usage $1
        exit 22
    fi
}

config_msr() {

    set_msr_cat $1

    if [[ "$2" = "-f" && "$4" = "-r" ]]; then
        set_msr_func $1 $3 $5
    else
        echo -e ""$CR"error"$CE": invalid $1 syntax"
        msr_usage
        exit 22
    fi

    if [[ "$6" != "-c" ]]; then
        echo -e ""$CR"error"$CE": invalid $1 syntax"
        msr_usage $1
        exit 22
    fi

    if [[ "$7" = "all" ]]; then
            config_all_cores "$r2 $r3 $r4"
            exit 0
    fi

    shift 6
    ncores="$#"
    cores="$@"

    config_select_cores "$r2 $r3 $r4" $ncores $cores
}
