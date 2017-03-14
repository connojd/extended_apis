#!/bin/bash

source extended_apis/tools/common.sh

vpid_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig vpid -f <fun> -c <cores>\n"
    echo -e ""$CY"syntax"$CE":    <fun> = on | off"
    echo -e ""$CY"syntax"$CE":    <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
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

    echo -e ""$CR"error"$CE": invalid vpid syntax"
    vpid_usage
    exit 22
}

config_vpid() {

    # set eapi_fun (r3) (and maybe vpid #, r4)
    if [[ "$2" = "-f" ]]; then
        set_vpid_func $3
    else
        echo -e ""$CR"error"$CE": invalid vpid syntax"
        vpid_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": invalid vpid syntax"
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
