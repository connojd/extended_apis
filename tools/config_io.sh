#!/bin/bash

port=""

io_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig io -f <fun> -p <port>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE":    <fun> = t | trap | p | pass"
    echo -e ""$CY"syntax"$CE":    <port> = all | 0x<hex>"
    echo -e ""$CY"syntax"$CE":    <hex> = 16bit port addr"
    echo -e ""$CY"syntax"$CE":    <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_io_regs() {

    r2="$cat_io"

    fun="$1"
    port="$2"

    if [[ "$port" = "all" ]]; then

        if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
            r3=$trap_all_io_access
            return
        elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
            r3=$pass_all_io_access
            return
        else
            echo -e ""$CR"error"$CE": invalid io function"
            io_usage
            exit 22
        fi
    fi

    # assume port conforms to syntax
    r4="$port"
    echo "r4: $r4"

    if [[ "$fun" = "trap" || "$fun" = "t" ]]; then
        r3=$trap_io_access
        return
    elif [[ "$fun" = "pass" || "$fun" = "p" ]]; then
        r3=$pass_io_access
        return
    else
        echo -e ""$CR"error"$CE": invalid io function"
        io_usage
        exit 22
    fi
}

config_io() {

    # set eapi_cat (r2) and eapi_fun (r3) (and maybe port #, r4)
    if [[ "$2" = "-f" && "$4" = "-p" ]]; then
        set_io_regs $3 $5
    else
        echo -e ""$CR"error"$CE": unknown io option(s): $2 $4"
        io_usage
        exit 22
    fi

    if [[ "$6" != "-c" ]]; then
        echo -e ""$CR"error"$CE": unknown io option: $6"
        io_usage
        exit 22
    fi

    if [[ "$7" = "all" ]]; then
            config_all_cores "$r2 $r3 $r4"
            exit 0
    fi

    shift 6
    ncores="$#"
    cores="$@"

    config_select_cores "$r2 $r3 $r4" $ncores $cores
}
