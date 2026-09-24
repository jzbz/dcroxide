//! Dump the rendered help for vector diffing.
use std::io::Write;

fn main() {
    // The application data directory `tools/helpgen` renders the
    // vector's defaults over (its `helpHome`), at the eighty columns
    // go-flags uses with no terminal on stdin, as the vector is made.
    let help = dcroxide_node::flags::render_help("dcroxide", "/home/user/.dcroxide", 80);
    std::io::stdout()
        .write_all(&help)
        .expect("write the help to stdout");
}
