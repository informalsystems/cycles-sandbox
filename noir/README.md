# Samples of Noir ZK circuits for cycles



- Flowcheck: single circuit implementation of Cycles flow conservation checking
- Hashing: micro benchmark using hash functions over lists
- Sorted lists: micro benchmark on sorting with advice vs hashing. Demonstrates
- Proof of Key: sample of using elliptic curve operations (baby jubjub)


## Installation

Follow https://github.com/noir-lang/noirup

- `nargo check` / `nargo info` display info about the circuit
- `nargo test` to run unit tests
- `nargo prove` runs the actual prover, using the input values in `Prover.toml`
- try changing the parameters in `src/main.nr` for different sizes
