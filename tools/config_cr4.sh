#!/bin/bash

cr4_usage() {
    printf ""$CY"syntax"$CE": ./vmconfig cr4 -f <fun> -b <bit>"
    printf " -c <cores>\n"
    echo -e ""$CY"syntax"$CE": <fun> = dump | t | trap | p | pass"
    echo -e ""$CY"syntax"$CE": <bit> = vme | pvi | tsd | de | pse |"
    echo -e ""$CY"syntax"$CE":         pae | mce | pge | pce | osfxsr |"
    echo -e ""$CY"syntax"$CE":         osxmmexcpt | umip | vmxe | smxe |"
    echo -e ""$CY"syntax"$CE":         fsgsbase | pcide | osxsave |"
    echo -e ""$CY"syntax"$CE":         smep | smap | pke"
    echo -e ""$CY"syntax"$CE": <cores> = all | [0-$(( $NUM_CORES - 1 ))]+"
}

set_cr4_bit() {
    case "$1" in
    "vme")
        r4=$cr4_vme
        ;;
    "pvi")
        r4=$cr4_pvi
        ;;
    "tsd")
        r4=$cr4_tsd
        ;;
    "de")
        r4=$cr4_de
        ;;
    "pse")
        r4=$cr4_pse
        ;;
    "pae")
        r4=$cr4_pae
        ;;
    "mce")
        r4=$cr4_mce
        ;;
    "pge")
        r4=$cr4_pge
        ;;
    "pce")
        r4=$cr4_pce
        ;;
    "osfxsr")
        r4=$cr4_osfxsr
        ;;
    "osxmmexcpt")
        r4=$cr4_osxmmexcpt
        ;;
    "umip")
        r4=$cr4_umip
        ;;
    "vmxe")
        r4=$cr4_vmxe
        ;;
    "smxe")
        r4=$cr4_smxe
        ;;
    "fsgsbase")
        r4=$cr4_fsgsbase
        ;;
    "pcide")
        r4=$cr4_pcide
        ;;
    "osxsave")
        r4=$cr4_osxsave
        ;;
    "smep")
        r4=$cr4_smep
        ;;
    "smap")
        r4=$cr4_smap
        ;;
    "pke")
        r4=$cr4_pke
        ;;
    *)
        echo -e ""$CR"error"$CE": invalid cr4 bit value"
    esac
}

set_cr4_regs() {

    r2="$cat_cr4"

    fun="$1"
    opt2="$2"
    bit="$3"

    if [[ "$fun" = "dump" ]]; then
        r3=$dump_cr4
        return
    fi

    if [[ "$opt2" != "-b" ]]; then
        echo -e ""$CR"error"$CE": second option must be -b"
        cr4_usage
        exit 22
    fi

    case "$fun" in
    "t"|"trap")
        r3=$trap_cr4
        ;;
    "p"|"pass")
        r3=$pass_through_cr4
        ;;
    *)
        echo -e ""$CR"error"$CE": invalid cr4 -f value"
        cr4_usage
        exit 22
    esac

    set_cr4_bit $bit
}

config_cr4() {

    # set eapi_cat (r2) and eapi_fun (r3)
    if [[ "$2" = "-f" ]]; then
        set_cr4_regs $3 $4 $5
    else
        echo -e ""$CR"error"$CE": specify function with -f <fun>"
        cr4_usage
        exit 22
    fi

    if [[ "$4" != "-c" && "$6" != "-c" ]]; then
        echo -e ""$CR"error"$CE": specify cores with -c <cores>"
        cr4_usage
        exit 22
    fi

    while [[ "$1" != "-c" ]]; do
        shift 1
    done

    if [[ "$2" = "all" ]]; then
            config_all_cores "$r2 $r3 $r4"
            exit 0
    fi

    shift 1
    ncores="$#"
    cores="$@"

    config_select_cores "$r2 $r3 $r4" $ncores $cores
}
