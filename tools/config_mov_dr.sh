#!/bin/bash

mov_dr_usage() {
    printf ""$CC"usage"$CE": ./vmconfig mov-dr -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_mov_dr_regs() {

    r2="$cat_mov_dr"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_mov_dr
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_mov_dr
        return
    else
        echo -e ""$CR"error"$CE": invalid mov-dr function"
        mov_dr_usage
        exit 22
    fi
}

config_mov_dr() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" != "-f" ]]; then
        echo -e ""$CR"error"$CE": first option must be -f"
        mov_dr_usage
        exit 22
    fi

    set_mov_dr_regs $3

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": second option must be -c"
        mov_dr_usage
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
