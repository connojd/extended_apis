#!/bin/bash

wbinvd_usage() {
    printf ""$CC"usage"$CE": ./vmconfig wbinvd -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_wbinvd_regs() {

    r2="$cat_wbinvd"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_wbinvd
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_wbinvd
        return
    else
        echo -e ""$CR"error"$CE": invalid wbinvd function"
        wbinvd_usage
        exit 22
    fi
}

config_wbinvd() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        wbinvd_usage
        exit 22
    fi

    set_wbinvd_regs $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        wbinvd_usage
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
