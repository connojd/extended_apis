#!/bin/bash

cr8_usage() {
    printf ""$CC"usage"$CE": ./vmconfig cr8 -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = tol (trap on load to CR8) |"
    echo -e ""$CY"syntax"$CE":         tos (trap on store from CR8) |"
    echo -e ""$CY"syntax"$CE":         pol (pass through on load to CR8) |"
    echo -e ""$CY"syntax"$CE":         pos (pass through on store from CR8)"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_cr8_regs() {

    r2="$cat_cr8"

    case "$1" in
    "tol")
        r3=$trap_cr8_load
        ;;
    "tos")
        r3=$trap_cr8_store
        ;;
    "pol")
        r3=$pass_through_cr8_load
        ;;
    "pos")
        r3=$pass_through_cr8_store
        ;;
    *)
        echo -e ""$CR"error"$CE": invalid cr8 function"
        cr8_usage
        exit 22
        ;;
    esac
}

config_cr8() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        cr8_usage
        exit 22
    fi

    set_cr8_regs $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        cr8_usage
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
