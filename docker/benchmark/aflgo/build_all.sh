#!/bin/bash
set -e

mkdir -p /d/p/aflgo
BUILD_DIR=/dcfuzz_bench/aflgo-build
mkdir -p $BUILD_DIR /dcfuzz_bench/aflgo-build/temp $BUILD_DIR/run


get_bin_name() {
    case "$1" in
        libming-4.7) echo "swftophp" ;;
        binutils-2.26) echo "cxxfilt" ;;
        *) echo "UNKNOWN target: $1" >&2; exit 1 ;;
    esac
}

build_aflgo_one() {
    TARGET=$1       # example : libming-4.7
    BUG=$2          # example : 2016-9827
    BIN_NAME=$(get_bin_name $TARGET)

    echo "[*] Building $TARGET:$BUG (binary: $BIN_NAME)"

    # setup path and script variable
    RUNDIR=$BUILD_DIR/run/RUNDIR-$TARGET-$BUG
    TMP_DIR=$BUILD_DIR/temp/temp-$TARGET-$BUG
    BUILD_SCRIPT=/dcfuzz_bench/$TARGET/build.sh

    DEFAULT_FLAGS="-g -fno-omit-frame-pointer -Wno-error"
    ASAN_FLAGS="-fsanitize=address"


    # Draw CFG and CG with BBtargets
    mkdir -p $RUNDIR $TMP_DIR
    cp /dcfuzz_bench/target_line/$BIN_NAME/$BUG $TMP_DIR/BBtargets.txt
    TARGET_LINE_FILE=$TMP_DIR/BBtargets.txt

    
    # setup environment variable
    export CC=/fuzzer/aflgo/afl-clang-fast
    export CXX=/fuzzer/aflgo/afl-clang-fast++
    ADDITIONAL="-targets=$TARGET_LINE_FILE -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    
    
    # instrumentation
    export CFLAGS="$DEFAULT_FLAGS $ADDITIONAL"
    export CXXFLAGS="$DEFAULT_FLAGS $ADDITIONAL"

    echo "************************test**************************"
    ls -al /fuzzer/aflgo

    bash $BUILD_SCRIPT

    echo "************************end**************************"

    cat $TARGET_LINE_FILE/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TARGET_LINE_FILE/BBnames2.txt \
	    && mv $TARGET_LINE_FILE/BBnames2.txt $TARGET_LINE_FILE/BBnames.txt
    cat $TARGET_LINE_FILE/BBcalls.txt | sort | uniq > $TARGET_LINE_FILE/BBcalls2/txt \
	    && mv $TARGET_LINE_FILE/BBcalls2.txt $TARGET_LINE_FILE/BBcalls.txt

    # calcuate distance
    echo "[*] Generating distance"
    cd $RUNDIR
    /fuzzer/aflgo/scripts/genDistance.sh $PWD $TMP_DIR $BIN_NAME

    # second distance calculate
    echo "[*] Rebuilding with distance info"
    rm -rf $RUNDIR
    mkdir -p $RUNDIR
    cd $RUNDIR


    export CFLAGS="$DEFAULT_FLAGS $ADDITIONAL"
    export CXXFLAGS="$DEFAULT_FLAGS $ADDITIONAL"
    ADDITIONAL="-distance=$TMP_DIR/distance.cfg.txt"
    export CFLAGS="$DEFAULT_FLAGS $ADDITIONAL"
    export CXXFLAGS="$DEFAULT_FLAGS $ADDITIONAL"
    
    bash $BUILD_SCRIPT

    # copy result
    OUT_BIN=/d/p/aflgo/${TARGET}-${BUG}
    mkdir -p $(dirname $OUT_BIN)

    cp $RUNDIR/${BIN_NAME} $OUT_BIN

    echo "final"
    exit 0

    rm -rf $TMP_DIR $RUNDIR

    echo "[+] Done: $TARGET:$BUG"

}

# Repeat the process for multiple bugs
build_with_aflgo() {
    TARGET=$1
    shift
    for BUG in "$@"; do
        build_aflgo_one "$TARGET" "$BUG"
    done
}


# execute and build each target and bug
build_with_aflgo "libming-4.7" \
    2016-9827 2016-9829 2016-9831 2017-9988 2017-11728 2017-11729

build_with_aflgo "binutils-2.26" \
    2016-4489 2016-4490 2016-4491 2016-4492 2016-6131 2016-4492-crash2

