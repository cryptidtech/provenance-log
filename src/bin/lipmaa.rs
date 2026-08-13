#![allow(
    clippy::needless_collect,
    clippy::unnecessary_wraps,
    clippy::too_many_lines,
    clippy::match_same_arms
)]
// SPDX-License-Identifier: FSL-1.1
use provenance_log::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("digraph lipmaa {{");
    println!("\tn0 [label=\"0\"]");
    for i in 1..17 {
        println!("\tn{i} [label=\"{i}\"]");
    }
    for i in 1..16 {
        println!("\tn{} -> n{}", i, i.lipmaa());
    }
    println!("}}");
    Ok(())
}
