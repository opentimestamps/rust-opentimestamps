
# OpenTimestamps Library for Rust

[OpenTimestamps is a service which provides provable timestamping using the Bitcoin
blockchain](https://petertodd.org/2016/opentimestamps-announcement)

This library is in very early stages and currently supports parsing and verification
of `.ots` files, but not serialization. Work needs to be done to support this, and
also to create documentation and examples.

In `src/bin/ots_info.rs` there is a simple application that reads a `.ots` file and
dumps its contents to stdout, as a basic usage example. It really just calls
`fmt::Display::fmt` on the `DetachedTimestampFile` structure; in the absense of any
other documentation, reading that function is a good starting point for seeing how
the data structures work. You can execute it with `cargo run -- <filename.ots>`

