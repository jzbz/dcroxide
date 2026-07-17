//! Dump the rendered help for vector diffing.
fn main() {
    print!("{}", dcroxide_node::flags::render_help("dcroxide"));
}
