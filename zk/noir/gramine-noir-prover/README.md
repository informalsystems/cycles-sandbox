# Noir prover in gramine

```
gramine-manifest -Dlog_level=error -Dhome=$HOME -Darch_libdir=/lib/x86_64-linux-gnu -Dra_type=dcap -Dra_client_linkable=1 -Dbin_path=`pwd`/target/release/gramine-noir-prover gramine-noir-prover.manifest.template gramine-noir-prover.manifest

gramine-sgx-sign --manifest gramine-noir-prover.manifest --output gramine-noir-prover.manifest.sgx

gramine-sgx ./gramine-noir-prover
```
