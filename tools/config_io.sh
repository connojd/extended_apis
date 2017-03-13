#!/bin/bash

source extended_apis/tools/common.sh

set_io_func {

    cat="$cat_io"

    if [[ "$2" -eq "all" ]]; then
        if [[ "$1" -eq "trap" || "$1" -eq "t" ]]; then
            func="0x4"
            return
        elif [[ "$1" -eq "pass" || "$1" -eq "p" ]]; then
            func="0x6"
            return
        else
            echo -e ""$CR"error"$CE": invalid args behavior for io"
        fi
    fi

    if (( "$2">=0x0 && "$2"<=0xffff )); then
        if [[ "$1" -eq "trap" || "$1" -eq "t" ]]; then
            func="0x3"
            return
        elif [[ "$1" -eq "pass" || "$1" -eq "p" ]]; then
            func="0x5"
            return
        else
            echo -e ""$CR"error"$CE": invalid args behavior for io"
        fi
    fi
}

config_io {

    case "$2" in
    "-b"|"behavior")
        case "$4" in
        "-p"|"--port")
            set_io_func $3 $5
            ;;
        *)
            echo -e ""$CR"error"$CE": must specify io port(s)"
            ;;
        esac
    ;;
    *)
        echo -e ""$CR"error"$CE": must specify io behavior"
        ;;
    esac

    case "$6" in
    "-c"|"--cores")
        case "$7" in
        "all")
            run_on_all_cores "$cat $func"
            exit 0
            ;;
        *)
            shift 6
            nargs="$#"

            for (( i=1; i<=nargs; i++ ))
            do
                if (( "$1">=0 && "$1"<NUM_CORES )); then
                    run_on_one_core "$1" "$cat $func"
                else
                    echo -e ""$CR"error"$CE": $1 is not a valid core number"
                    exit 22
                fi
                shift
            done
            exit 0
            ;;
        esac
    ;;
    *)
        echo -e ""$CR"error"$CE": must specify cores"
        ;;
    esac
}
