#!/bin/bash

run_gokart() {
    go install github.com/praetorian-inc/gokart@${GOKART_VERSION:=latest}
    if [[ $? -ne "0" ]]; then
        echo "Failed to install gokart"; return 1
    fi

    CMD="gokart scan . -s -o gokart_result.json"
    if [[ ! -z ${GOKART_CONFIG_LOC:=} ]]; then
        CMD=$CMD" -i ${GOKART_CONFIG_LOC}"
    fi
    eval $CMD 

    NUM_ISSUES=$(cat gokart_result.json | jq '.runs[0].results | length')
    if [[ $NUM_ISSUES -ne "0" ]]; then
        echo "gokart found ${NUM_ISSUES} issues; see gokart_result.json"; return 1
    fi
}

# Check for vulnerabilities using static analysis
run_gokart
# If we add others in the future we can change this so that all analyses run and we
# exit with non-zero code if any fail.
if [[ $? -ne "0" ]]; then
    exit 1
fi
