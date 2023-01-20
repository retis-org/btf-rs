# Btf-rs

Rust library for the [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html).
The BPF Type Format is a metadata format encoding debugging information such as
types, function prototypes, structure layouts, etc. and is often used, but not
limited, to deal with [eBPF](https://ebpf.io) programs.

This library was initially developed for a kernel packet tracking tool,
[packet-tracer](https://github.com/net-trace/packet-tracer), but is exported on
its own as there are no specific ties with the mentioned tool and can be
(re)used in all kinds of Rust projects.

```toml
[dependencies]
btf-rs = "0.1"
```

The [integration tests](tests/integration_test.rs) give good examples on how to
use this library.
