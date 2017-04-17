
# OpenTimestamps Library for Rust

[OpenTimestamps is a service which provides provable timestamping using the Bitcoin
blockchain](https://petertodd.org/2016/opentimestamps-announcement)

This library is in early stages. It currently supports parsing and serialization
of `.ots` files, and can play them forward to compute the eventual hashes that
actually wind up in the chain.

There is lots of remaining work to do as far as documentation and examples.

A timestamp viewer using this library is available at [wpsoftware.net](https://www.wpsoftware.net/ots/).
Its [source code is here](https://github.com/apoelstra/ots-viewer).

In `src/bin/ots_info.rs` there is a simple application that reads a `.ots` file and
dumps its contents to stdout, as a basic usage example. It really just calls
`fmt::Display::fmt` on the `DetachedTimestampFile` structure; in the absense of any
other documentation, reading that function is a good starting point for seeing how
the data structures work. You can execute it with `cargo run -- <filename.ots>`

[Documentation](https://www.wpsoftware.net/rustdoc/opentimestamps/)

