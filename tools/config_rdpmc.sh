#!/bin/bash

rdpmc_usage() {
    printf ""$CC"usage"$CE": ./vmconfig rdpmc -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_rdpmc_regs() {

    r2="$cat_rdpmc"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_rdpmc
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_rdpmc
        return
    else
        echo -e ""$CR"error"$CE": invalid rdpmc function"
        rdpmc_usage
        exit 22
    fi
}

config_rdpmc() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        rdpmc_usage
        exit 22
    fi

    set_rdpmc_regs $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        rdpmc_usage
        exit 22
    fi

    if [[ "$5" = "all" ]]; then
            config_all_cores "$r2 $r3"
            exit 0
    fi

    shift 4
    ncores="$#"
    cores="$@"

    config_select_cores "$r2 $r3" $ncores $cores
}
