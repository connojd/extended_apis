#!/bin/bash

cr3_usage() {
    printf ""$CC"usage"$CE": ./vmconfig cr3 -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = tol (trap on load to CR3 on core(s) <cores>) |"
    echo -e ""$CY"syntax"$CE":         tos (trap on store from CR3 on core(s) <cores>) |"
    echo -e ""$CY"syntax"$CE":         pol (pass through on load to CR3 on core(s) <cores>) |"
    echo -e ""$CY"syntax"$CE":         pos (pass through on store from CR3 on core(s) <cores>)"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_cr3_regs() {

    r2="$cat_cr3"

    case "$1" in
    "tol")
        r3=$trap_cr3_load
        ;;
    "tos")
        r3=$trap_cr3_store
        ;;
    "pol")
        r3=$pass_through_cr3_load
        ;;
    "pos")
        r3=$pass_through_cr3_store
        ;;
    *)
        echo -e ""$CR"error"$CE": invalid cr3 function"
        cr3_usage
        exit 22
        ;;
    esac
}

config_cr3() {

    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        cr3_usage
        exit 22
    fi

    set_cr3_regs $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        cr3_usage
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
