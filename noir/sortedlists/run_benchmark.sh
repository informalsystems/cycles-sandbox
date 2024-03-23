#!/bin/bash

# Clear build folder
rm -r build_circuits
mkdir -p build_circuits

# Loop over sizes
for i in $(seq 4 10)
do

    # Generate a new build/2^{i} folder
    nargo new build_circuits/2^${i}
    pushd build_circuits/2^${i}

    # replace {{N}} in src/main.nr    
    cat ../../src/main.nr | CIRCUIT_SIZE=$((2**$i)) envsubst > ./src/main.nr
    
    # Generate the Prover.toml with an array
    echo >> ./Prover.toml "x = ["    
    for j in $(seq 1 $((2**i)))
    do
	cat >> ./Prover.toml <<EOF
	${j},
EOF
    done
    echo >> ./Prover.toml "]"
    
    # Run the experiment
    nargo compile
    nargo info | tee ../info_${i}.txt

    { time nargo prove; } 2> ../time_proof_${i}.txt

    popd
done

# Collect results
