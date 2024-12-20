# arkworks prover in gramine

```
gramine-manifest -Dlog_level=error -Dhome=$HOME -Darch_libdir=/lib/x86_64-linux-gnu -Dra_type=dcap -Dra_client_linkable=1 -Dbin_path=`pwd`/target/release/arkworks-gramine arkworks-gramine.manifest.template arkworks-gramine.manifest

gramine-sgx-sign --manifest arkworks-gramine.manifest --output arkworks-gramine.manifest.sgx

gramine-sgx ./arkworks-gramine
```
