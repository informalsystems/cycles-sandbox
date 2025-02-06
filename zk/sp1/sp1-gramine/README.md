# SP1 prover in gramine

```
gramine-manifest -Dlog_level=error -Dhome=$HOME -Darch_libdir=/lib/x86_64-linux-gnu -Dra_type=dcap -Dra_client_linkable=1 -Dbin_path=`pwd`/target/release/sp1-gramine sp1-gramine.manifest.template sp1-gramine.manifest

gramine-sgx-sign --manifest sp1-gramine.manifest --output sp1-gramine.manifest.sgx

gramine-sgx ./sp1-gramine
```
