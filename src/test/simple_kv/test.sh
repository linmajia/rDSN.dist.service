#!/bin/bash

bin=./dsn.dist.service.test.simple_kv
cases=()

function run_single()
{
    prefix=$1
    echo "${bin} ${prefix}.ini ${prefix}.act"
    "${bin}" "${prefix}.ini" "${prefix}.act"
    ret=$?
    log=$(find . -name log.1.txt -print -quit)
    if [ -n "${log}" ]; then
        grep -v FAILURE_DETECT "${log}" | grep -v BEACON | grep -v beacon | grep -v THREAD_POOL_FD >"${prefix}.log"
        rm -- "${log}"
    fi

    if [ "${ret}" -ne 0 ]; then
        echo "run ${prefix} failed, return value = ${ret}"
        if [ -f core ]; then
            echo "---- gdb ./dsn.rep_tests.simple_kv core ----"
            gdb ./dsn.rep_tests.simple_kv core -ex "thread apply all bt" -ex "set pagination 0" -batch
        fi
        exit -1
    fi
}

function run_case()
{
    id=$1

    if [ -d "case-${id}" ]; then
        cd "case-${id}"
        ./test.sh
        if [ $? -ne 0 ]; then
            exit -1
        fi
        cd ..
        return
    fi

    if [ -f "case-${id}.act" ]; then
        rm -rf data core*
        run_single "case-${id}"
        return
    fi

    subcases=$(find . -maxdepth 1 -name "case-${id}-[0-9].act" -print |
        sed -n 's|^\./case-[0-9][0-9][0-9]-\([0-9]\).act$|\1|p' | sort -u)
    if [ -n "${subcases}" ]; then
        rm -rf data core*
        for subid in ${subcases}; do
            run_single "case-${id}-${subid}"
        done
        return
    fi

    echo "case-${id} not found"
    exit -1
}

if [ $# -eq 0 ]; then
    if [ -n "${DSN_TEST_FILTER}" ]; then
        IFS=',:' read -ra cases <<< "${DSN_TEST_FILTER}"
    else
        while IFS= read -r case_id; do
            cases+=("${case_id}")
        done < <(find . -maxdepth 1 -name 'case-*' -print |
            sed -n 's|^\./case-\([0-9][0-9][0-9]\).*$|\1|p' | sort -u)
    fi
else
    cases=("$@")
fi

if [ ${#cases[@]} -gt 0 ]; then
    for id in "${cases[@]}"; do
        run_case "${id}"
        echo
    done
fi
