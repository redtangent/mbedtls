#!/bin/sh

# samples-test.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# Tests each of the example programs with at least one single positive test
# case, and confirms that each works correctly in a single default use case.
#

set -u

TESTS=0
FAILS=0
SKIPS=0

MEMCHECK=0
FILTER='.*'
EXCLUDE='^$'

SHOW_TEST_NUMBER=0
RUN_TEST_NUMBER=''

PRESERVE_LOGS=0

# Also pick a unique name for intermediate files
OUT_LOG="out_log.$$"

trap cleanup INT TERM HUP


print_usage() {
    echo "Usage: $0 [options]"
    printf "  -h|--help\tPrint this help.\n"
    printf "  -m|--memcheck\tCheck memory leaks and errors.\n"
    printf "  -f|--filter\tOnly matching tests are executed (BRE; default: '$FILTER')\n"
    printf "  -e|--exclude\tMatching tests are excluded (BRE; default: '$EXCLUDE')\n"
    printf "  -p|--preserve-logs\tPreserve logs of successful tests as well\n"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--filter)
                shift; FILTER=$1
                ;;
            -e|--exclude)
                shift; EXCLUDE=$1
                ;;
            -m|--memcheck)
                MEMCHECK=1
                ;;
           -p|--preserve-logs)
                PRESERVE_LOGS=1
                ;;
           -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

# skip next test if the flag is not enabled in config.h
requires_config_enabled() {
    if grep "^#define $1" $CONFIG_H > /dev/null; then :; else
        SKIP_NEXT="YES"
    fi
}

# skip next test if the flag is enabled in config.h
requires_config_disabled() {
    if grep "^#define $1" $CONFIG_H > /dev/null; then
        SKIP_NEXT="YES"
    fi
}

check_files() {
    # Compare files
    diff "$1" "$2" > $OUT_LOG

    # Check diff exit code
    if [ $? -ne 0 ]; then
        return 1
    else
        return 0
    fi
}

# Usage: run_sample_program path program parameters test [options]
# Options:  -p pattern  pattern that must be present in the sample output
#           -a pattern  pattern that must be absent in the sample output
#           -F call shell function on server output
run_sample_program() {
    CMD_PATH="$1"
    shift 1

    CMD="$1"
    shift 1

    PARAMS="$1"
    shift 1

    TEST="$1"
    shift 1

    TEST_CMD="$CMD_PATH$CMD"

    print_name "$CMD_PATH$CMD - $TEST"

    # prepend valgrind to our commands if active
    if [ "$MEMCHECK" -gt 0 ]; then
        TEST_CMD="valgrind --leak-check=full $TEST_CMD"
    fi

    echo "$TEST_CMD $PARAMS" > $OUT_LOG

    # Execute the test program
    $TEST_CMD $PARAMS >> $OUT_LOG 2>&1
    EXIT_VAL=$?

    # check server exit code
    if [ $EXIT_VAL -ne 0 ]; then
        fail "Sample failed with error code $EXIT_VAL"
        return
    fi

    # Check other assertions
    # lines beginning with == are added by valgrind, ignore them
    # lines with 'Serious error when reading debug info', are valgrind issues as well
    while [ $# -gt 0 ]
    do
        case $1 in
            "-p")
                if grep -v '^==' $OUT_LOG | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then :; else
                    fail "pattern '$2' MUST be present in the sample program output"
                    return
                fi
                ;;

            "-a")
                if grep -v '^==' $OUT_LOG | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then
                    fail "pattern '$2' MUST NOT be present in the sample program output"
                    return
                fi
                ;;

            "-F")
                if ! $2 > $OUT_LOG; then
                    fail "function call to '$2' failed"
                    return
                fi
                ;;

            *)
                echo "Unknown test option: $1" >&2
                exit 1
        esac
        shift 2
    done

    # check valgrind's results
    if [ "$MEMCHECK" -gt 0 ]; then
        if has_mem_err $OUT_LOG; then
            fail "Sample has memory errors"
            return
        fi
    fi

    # if we're here, everything is ok
    echo "PASS"
    if [ "$PRESERVE_LOGS" -gt 0 ]; then
        mv $OUT_LOG sample-out-${TESTS}.log
    fi

    rm -f $OUT_LOG
}

# print_name <name>
print_name() {
    TESTS=$(( $TESTS + 1 ))
    LINE=""

    if [ "$SHOW_TEST_NUMBER" -gt 0 ]; then
        LINE="$TESTS "
    fi

    LINE="$LINE$1"
    printf "$LINE "
    LEN=$(( 72 - `echo "$LINE" | wc -c` ))
    for i in `seq 1 $LEN`; do printf '.'; done
    printf ' '

}

# fail <message>
fail() {
    echo "FAIL"
    echo "  ! $1"

    mv $OUT_LOG sample-out-${TESTS}.log
    echo "  ! outputs saved to sample-out-${TESTS}.log"

    if [ "X${USER:-}" = Xbuildbot -o "X${LOGNAME:-}" = Xbuildbot ]; then
        echo "  ! sample output:"
        cat sample-out-${TESTS}.log
        echo ""
    fi

    FAILS=$(( $FAILS + 1 ))
}

cleanup() {
    rm -f $LOG_OUT
    exit 1
}


################################################################################
# MAIN

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

get_options "$@"



################################################################################
# AES samples

echo "Test data - 12345678790ABCDEFGHIJKLMNOPQRSTUV" > plaintext.data

# programs/aes/aescrypt2
run_sample_program "programs/aes/" "aescrypt2" "0 plaintext.data ciphertext.data 112233445566778899AABBCCDDEEFF00" "encrypt 128-bit key"

run_sample_program "programs/aes/" "aescrypt2" "1 ciphertext.data out.data 112233445566778899AABBCCDDEEFF00" "decrypt 128-bit key" -F "check_files plaintext.data out.data"

rm -f ciphertext.data out.data


# programs/aes/crypt_and_hash
run_sample_program "programs/aes/" "crypt_and_hash" "0 plaintext.data
ciphertext.data AES-128-CBC SHA256 112233445566778899AABBCCDDEEFF00" "encrypt 128-bit key"

run_sample_program "programs/aes/" "crypt_and_hash" "1 ciphertext.data out.data AES-128-CBC SHA256 112233445566778899AABBCCDDEEFF00" "decrypt 128-bit key" -F "check_files plaintext.data out.data"

rm -f ciphertext.data out.data


# programs/hash/hash
run_sample_program "programs/hash/" "generic_sum" "SHA256 plaintext.data" "generate hash SHA256"

# TODO - redirect output from previous command to out.data for this test
#run_sample_program "programs/hash/" "generic_sum" "SHA256 -c out.data" "check hash SHA256"


# programs/hash/hello
run_sample_program "programs/hash/" "hello" "" "default output" -p "MD5('Hello, world!') = 6cd3556deb0da54bca060b4c39479839"


# programs/pkey/dh_genprime
run_sample_program "programs/pkey/" "dh_genprime" "" "default output" -p "Exporting the value in dh_prime.txt... ok"


# programs/pkey/rsa_genkey
run_sample_program "programs/pkey/" "rsa_genkey" "" "default output" -p "Exporting the private key in rsa_priv.txt... ok"


# programs/pkey/dh_server
# TODO


# programs/pkey/dh_client
# TODO


# programs/pkey/ecdh_curve25519
run_sample_program "programs/pkey/" "ecdh_curve25519" "" "default output" -p "Checking if both computed secrets are equal... ok"


# programs/pkey/ecdsa
run_sample_program "programs/pkey/" "ecdsa" "" "default output" -p "Verifying signature... ok"

# programs/pkey/key_app
# TODO

# programs/pkey/key_app_writer
# TODO

# programs/pkey/mpi_demo
run_sample_program "programs/pkey/" "mpi_demo" "" "default output" -p "Z (decrypted)  = Y^D mod N = 55555"

# programs/pkey/pk_decrypt
# TODO

# programs/pkey/pk_encrypt
# TODO

# programs/pkey/pk_sign
# TODO

# programs/pkey/pk_verify
# TODO

# programs/pkey/rsa_decrypt
# TODO

# programs/pkey/rsa_encrypt
# TODO

# programs/pkey/rsa_sign
# TODO

# programs/pkey/rsa_verify
# TODO

# programs/pkey/rsa_sign_pss
# TODO

# programs/pkey/rsa_verify_pss
# TODO

# programs/random/gen_entropy
run_sample_program "programs/random/" "gen_entropy" "test.out" "default output" -p "Generating 48kb of data in file 'test.out'... 100.0% done"

# programs/random/gen_random_ctr_drbg
run_sample_program "programs/random/" "gen_random_ctr_drbg" "test.out" "default output" -p "Generating 768kb of data in file 'test.out'... 100.0% done"

# programs/random/gen_random_havege
# TODO

# programs/ssl/dtls_client
# TODO

# programs/ssl/dtls_server
# TODO

# programs/ssl/mini_client
# TODO

# programs/ssl/ssl_client1
# TODO

# programs/ssl/ssl_client2
# TODO

# programs/ssl/ssl_fork_server
# TODO

# programs/ssl/ssl_mail_client
# TODO

# programs/ssl/ssl_pthread_server
# TODO

# programs/ssl/ssl_server
# TODO

# programs/ssl/ssl_server2
# TODO

# programs/test/benchmark
run_sample_program "programs/test/" "benchmark" "" "default output" -p "ECDH-Curve25519          :"

# programs/test/selftest
run_sample_program "programs/test/" "selftest" "" "default output" -p "[ All tests PASS ]"

# programs/test/ssl_cert_test
# TODO

# programs/test/udp_proxy
# TODO

# programs/util/pem2der
# TODO

# programs/util/strerror
run_sample_program "programs/util/" "strerror" "-0x3d00" "default output" -p "Last error was: -0x3d00 - PK - Invalid key tag or value"

# programs/x509/cert_app
# TODO

# programs/x509/cert_req
# TODO

# programs/x509/cert_write
# TODO

# programs/x509/crl_app
# TODO

# programs/x509/req_app
# TODO


################################################################################
# Final report

echo "------------------------------------------------------------------------"

if [ $FAILS = 0 ]; then
    printf "PASSED"
else
    printf "FAILED"
fi
PASSES=$(( $TESTS - $FAILS ))
echo " ($PASSES / $TESTS tests ($SKIPS skipped))"

exit $FAILS
