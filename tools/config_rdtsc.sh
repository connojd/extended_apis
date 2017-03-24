#!/bin/bash

rdtsc_usage() {
    printf ""$CC"usage"$CE": ./vmconfig $1 -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"

    printf ""$CG"note"$CE": If rdtscp is allowed to trap (see serial"
    printf " output on startup)\n"
    printf ""$CG"note"$CE": then rdtsc traps (passes through) iff rdtscp\n"
    printf ""$CG"note"$CE": traps (passes through).  If rdtscp is not\n"
    printf ""$CG"note"$CE": allowed to trap by the hardware, then it always\n"
    printf ""$CG"note"$CE": passes through, regardless of rdtsc controls\n"
}

set_rdtsc_regs() {

    r2="$cat_rdtsc"
    fun="$2"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_rdtsc
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_rdtsc
        return
    else
        echo -e ""$CR"error"$CE": invalid $1 function"
        rdtsc_usage $1
        exit 22
    fi
}

config_rdtsc() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        rdtsc_usage $1
        exit 22
    fi

    set_rdtsc_regs $1 $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        rdtsc_usage $1
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
