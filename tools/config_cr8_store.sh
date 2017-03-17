#!/bin/bash

cr8_store_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig cr8-store -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_cr8_store_regs() {

    r2="$cat_cr8_store"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_cr8_store
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_cr8_store
        return
    else
        echo -e ""$CR"error"$CE": invalid cr8-store function"
        cr8_store_usage
        exit 22
    fi
}

config_cr8_store() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_cr8_store_regs $3
    else
        echo -e ""$CR"error"$CE": unknown cr8-store option(s): $2 $4"
        cr8_store_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown cr8-store option: $4"
        cr8_store_usage
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
