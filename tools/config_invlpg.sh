#!/bin/bash

invlpg_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig inv{lpg|pcid} -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"

    printf ""$CC"note"$CE": If invpcid is allowed to trap (see serial"
    printf " output on startup)\n"
    printf ""$CC"note"$CE": then invlpg traps (passes through) iff invpcid\n"
    printf ""$CC"note"$CE": traps (passes through).  If invpcid is not\n"
    printf ""$CC"note"$CE": allowed to trap by the hardware, then it always\n"
    printf ""$CC"note"$CE": passes through, regardless of invlpg controls\n"
}

set_invlpg_regs() {

    r2="$cat_invlpg"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_invlpg
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_invlpg
        return
    else
        echo -e ""$CR"error"$CE": invalid inv{lpg|pcid} function"
        invlpg_usage
        exit 22
    fi
}

config_invlpg() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_invlpg_regs $3
    else
        echo -e ""$CR"error"$CE": unknown inv{lpg|pcid} option(s): $2 $4"
        invlpg_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown inv{lpg|pcid} option: $4"
        invlpg_usage
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
