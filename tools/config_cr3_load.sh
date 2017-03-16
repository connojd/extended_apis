#!/bin/bash

cr3_load_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig cr3-load -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_cr3_load_regs() {

    r2="$cat_cr3_load"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_cr3_load
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_cr3_load
        return
    else
        echo -e ""$CR"error"$CE": invalid cr3_load function"
        cr3_load_usage
        exit 22
    fi
}

config_cr3_load() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_cr3_load_regs $3
    else
        echo -e ""$CR"error"$CE": unknown cr3-load option(s): $2 $4"
        cr3_load_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown cr3-load option: $4"
        cr3_load_usage
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
