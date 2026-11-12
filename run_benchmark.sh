#!/bin/bash
# Usage: ./run_benchmark.sh      (asks for your sudo password; takes about 5 minutes)
# Measures the plain learning switch and the access-controlled setup, each with 1 and with 2 clients,
# three times over (a fresh network every time), so the chart can use the median,
# writes results/benchmark.csv, then draws results/benchmark.png and results/benchmark_table.md.
cd "$(dirname "$0")"
mkdir -p results
rm -f results/benchmark.csv results/benchmark.png results/benchmark_table.md

# The controller needs its secret token file (same as start.sh).
if [ ! -s api_token ]; then
    (umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > api_token)
fi

# run_mode <name> <ryu app>
run_mode() {
    echo "=== mode: $1 ($2)"
    # mn -c first: it also kills ryu-manager, so Ryu must be started after it.
    sudo mn -c > /dev/null 2>&1
    PYTHONPATH=. ./.venv/bin/ryu-manager "$2" > "results/ryu_$1.log" 2>&1 &
    RYU_PID=$!
    sleep 5
    for run in 1 2 3; do
        for n in 1 2; do
            echo "--- $1, $n client(s), run $run of 3"
            sudo python3 benchmark.py --mode "$1" --clients "$n" --run "$run" --csv results/benchmark.csv
        done
    done
    kill $RYU_PID 2>/dev/null
    wait $RYU_PID 2>/dev/null
}

run_mode plain ryu.app.simple_switch_13
run_mode controlled sdn_controller.py

python3 plot_results.py
echo "Done: results/benchmark.csv, results/benchmark.png, results/benchmark_table.md"
