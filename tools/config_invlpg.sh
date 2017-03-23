#!/bin/bash

invlpg_usage() {
    printf ""$CC"usage"$CE": ./vmconfig "$1" -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"

    printf ""$CG"note"$CE": If invpcid is allowed to trap (see serial"
    printf " output on startup)\n"
    printf ""$CG"note"$CE": then invlpg traps (passes through) iff invpcid\n"
    printf ""$CG"note"$CE": traps (passes through).  If invpcid is not\n"
    printf ""$CG"note"$CE": allowed to trap by the hardware, then it always\n"
    printf ""$CG"note"$CE": passes through, regardless of invlpg controls\n"
}

set_invlpg_regs() {

    r2="$cat_invlpg"
    fun="$2"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_invlpg
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_invlpg
        return
    else
        echo -e ""$CR"error"$CE": invalid "$1" function"
        invlpg_usage $1
        exit 22
    fi
}

config_invlpg() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        invlpg_usage $1
        exit 22
    fi

    set_invlpg_regs $1 $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        invlpg_usage $1
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
