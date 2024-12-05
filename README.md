# dcap-ffi
A quick-and-dirty hack to provide dcap-rs via standard C FFI.

This includes both an export of the dcap-rs verification functionality as a C FFI interface "verify_quote_dcapv4".
It also contains a quick-and-dirty implementation of the on-chain PCCS interface in pccs.rs