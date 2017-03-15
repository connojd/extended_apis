#!/bin/bash

rdtsc_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig rdtsc[p] -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"

    printf ""$CC"note"$CE": rdtsc traps (passes-through) iff rdtscp traps"
    printf " (passes-through)\n"
}

set_rdtsc_regs() {

    r2="$cat_rdtsc"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_rdtsc
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_rdtsc
        return
    else
        echo -e ""$CR"error"$CE": invalid rdtsc[p] function"
        rdtsc_usage
        exit 22
    fi
}

config_rdtsc() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_rdtsc_regs $3
    else
        echo -e ""$CR"error"$CE": unknown rdtsc[p] option(s): $2 $4"
        rdtsc_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown rdtsc[p] option: $4"
        rdtsc_usage
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
