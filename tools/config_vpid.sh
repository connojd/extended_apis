#!/bin/bash

source extended_apis/tools/common.sh

vpid_usage() {
    printf ""$CC"usage"$CE": ./vmconfig vpid -f <fun> -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = on | off"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_vpid_func() {

    r2=$cat_vpid
    fun=$1

    if [[ "$fun" = "on" ]]; then
        r3=$vpid_on
        return
    fi

    if [[ "$fun" = "off" ]]; then
        r3=$vpid_off
        return
    fi

    echo -e ""$CR"error"$CE": invalid vpid function"
    vpid_usage
    exit 22
}

config_vpid() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        vpid_usage
        exit 22
    fi

    set_vpid_func $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        vpid_usage
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
