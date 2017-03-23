#!/bin/bash

desc_table_usage() {
    printf ""$CC"usage"$CE": ./vmconfig desc-table -f <fun>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"

    printf ""$CG"note"$CE": Configuring desc-table to trap will enable trapping\n"
    printf ""$CG"note"$CE": on LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, and STR.\n"
    printf ""$CG"note"$CE": Configuring desc-table to pass through will cause\n"
    printf ""$CG"note"$CE": all the instructions above to pass through.\n"
}

set_desc_table_regs() {

    r2="$cat_desc_table"
    fun="$1"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_desc_table
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_through_desc_table
        return
    else
        echo -e ""$CR"error"$CE": invalid desc-table function"
        desc_table_usage
        exit 22
    fi
}

config_desc_table() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" && "$4" = "-c" ]]; then
        set_desc_table_regs $3
    else
        echo -e ""$CR"error"$CE": unknown desc-table option(s): $2 $4"
        desc_table_usage
        exit 22
    fi

    if [[ "$4" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown desc-table option: $4"
        desc_table_usage
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
