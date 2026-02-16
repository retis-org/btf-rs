use std::{path::PathBuf, time::Instant};

use anyhow::{bail, Result};
use btf_rs::*;
use clap::{builder::PossibleValuesParser, Parser};

#[cfg(feature = "regex")]
use regex::Regex;

#[derive(Parser)]
#[command(about = "Benchmarking utility to measure btf-rs performances")]
struct Args {
    #[arg(
        long,
        short,
        default_value = "50",
        value_parser = clap::value_parser!(u32).range(1..),
        help = "Number of iterations to run each test case"
    )]
    iterations: u32,
    #[arg(
        long,
        default_value = "default",
        value_parser=PossibleValuesParser::new([
            "default", "cache", "mmap",
        ]),
        help = "Backend to use for storing parsed BTF data",
    )]
    backend: String,
    #[arg(
        long,
        default_value = "/sys/kernel/btf/vmlinux",
        help = "Path to the base BTF file"
    )]
    base: PathBuf,
    #[arg(long, help = "Path to a split BTF file extending `--base`")]
    split: Option<PathBuf>,
    #[arg(long, help = "Id to use for the resolving a base type")]
    id: u32,
    #[arg(long, help = "Name to use for the resolving base types")]
    name: String,
    #[cfg(feature = "regex")]
    #[arg(long, help = "Regex to use for the resolving base types")]
    regex: Option<String>,
}

macro_rules! test {
    ($name:expr, $iterations:expr, $insts:block) => {
        let now = Instant::now();
        for _ in 0..$iterations {
            $insts
        }
        println!(
            "{} {} ns",
            $name,
            now.elapsed().as_nanos() / $iterations as u128
        );
    };
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut btf = match args.backend.as_str() {
        "default" => {
            test!("Btf::from_file", args.iterations, {
                let _ = Btf::from_file(&args.base)?;
            });
            Btf::from_file(&args.base)?
        }
        "cache" => {
            test!("Btf::cache_from_file", args.iterations, {
                let _ = Btf::from_file_with_backend(&args.base, Backend::Cache)?;
            });
            Btf::from_file_with_backend(&args.base, Backend::Cache)?
        }
        "mmap" => {
            test!("Btf::mmap_from_file", args.iterations, {
                let _ = Btf::from_file_with_backend(&args.base, Backend::Mmap)?;
            });
            Btf::from_file_with_backend(&args.base, Backend::Mmap)?
        }
        x => bail!("Unknown backend {x}"),
    };

    if let Some(split) = &args.split {
        test!("Btf::from_split_file", args.iterations, {
            let _ = Btf::from_split_file(split, &btf)?;
        });
        btf = Btf::from_split_file(split, &btf)?;
    }

    test!("Btf::resolve_type_by_id", args.iterations, {
        let _ = btf.resolve_type_by_id(args.id)?;
    });

    let r#type = btf.resolve_type_by_id(args.id)?;
    test!("Btf::resolve_name", args.iterations, {
        let _ = btf
            .resolve_name(
                r#type
                    .as_btf_type()
                    .expect("Type (from `--id`) not a `dyn BtfType`"),
            )
            .expect("Name not found for type (from `--id`)");
    });

    test!("Btf::resolve_ids_by_name", args.iterations, {
        let res = btf.resolve_ids_by_name(&args.name)?;
        assert!(!res.is_empty(), "Ids not found by name");
    });

    test!("Btf::resolve_types_by_name", args.iterations, {
        let res = btf.resolve_types_by_name(&args.name)?;
        assert!(!res.is_empty(), "Types not found by name");
    });

    #[cfg(feature = "regex")]
    if let Some(regex) = &args.regex {
        let re = Regex::new(regex)?;
        test!("Btf::resolve_ids_by_regex", args.iterations, {
            let res = btf.resolve_ids_by_regex(&re)?;
            assert!(!res.is_empty(), "Ids not found by regex");
        });
    }

    #[cfg(feature = "regex")]
    if let Some(regex) = &args.regex {
        let re = Regex::new(regex)?;
        test!("Btf::resolve_types_by_regex", args.iterations, {
            let res = btf.resolve_types_by_regex(&re)?;
            assert!(!res.is_empty(), "Types not found by regex");
        });
    }

    Ok(())
}
