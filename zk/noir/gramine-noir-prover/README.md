# Noir prover in gramine

```
$ sudo apt install libc++1 libc++-dev    # optional dependency

$ gramine-manifest \
    -Dlog_level=error \
    -Dhome=$HOME \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dra_type=dcap -Dra_client_linkable=1 \
    -Dbin_path=`pwd`/target/release/gramine-noir-prover \
    -Dnargo_path="$HOME"/.nargo/bin/nargo \
    -Dbb_path="$HOME"/.bb/bb \
    gramine-noir-prover.manifest.template gramine-noir-prover.manifest

$ gramine-sgx-sign --manifest gramine-noir-prover.manifest --output gramine-noir-prover.manifest.sgx

$ gramine-sgx ./gramine-noir-prover
Gramine is starting. Parsing TOML manifest file, this may take some time...
Running 'nargo execute'...
nargo --version output:
nargo version = 0.36.0
noirc version = 0.36.0+801c71880ecf8386a26737a5d8bb5b4cb164b2ab
(git version hash: 801c71880ecf8386a26737a5d8bb5b4cb164b2ab, is dirty: false)

Running 'bb prove'...
bb --version output:
0.58.0
```
