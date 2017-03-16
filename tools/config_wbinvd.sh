#!/bin/bash

wbinvd_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig wbinvd -f <fun>"
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

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_wbinvd_regs $3
    else
        echo -e ""$CR"error"$CE": unknown wbinvd option(s): $2 $4"
        wbinvd_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown wbinvd option: $4"
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
