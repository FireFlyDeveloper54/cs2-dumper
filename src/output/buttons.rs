use std::collections::BTreeMap;
use std::fmt::{self, Write};

use super::ident::{
    csharp_identifier, cpp_identifier, rust_identifier, IdentifierAllocator,
};
use super::{zig_ident, ButtonMap, CodeWriter, Formatter};

impl CodeWriter for ButtonMap {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace CS2Dumper", false, |fmt| {
            writeln!(fmt, "// Module: client.dll")?;

            fmt.block("public static class Buttons", false, |fmt| {
                let mut names = IdentifierAllocator::default();
                for (name, value) in self {
                    writeln!(
                        fmt,
                        "public const nint {} = {:#X};",
                        names.allocate(csharp_identifier(name)),
                        value
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#pragma once\n")?;
        writeln!(fmt, "#include <cstddef>")?;
        writeln!(fmt, "#include <cstdint>\n")?;

        fmt.block("namespace cs2_dumper", false, |fmt| {
            writeln!(fmt, "// Module: client.dll")?;

            fmt.block("namespace buttons", false, |fmt| {
                let mut names = IdentifierAllocator::default();
                for (name, value) in self {
                    writeln!(
                        fmt,
                        "constexpr std::ptrdiff_t {} = {:#X};",
                        names.allocate(cpp_identifier(name)),
                        value
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content = {
            let buttons: BTreeMap<_, _> = self.iter().collect();

            BTreeMap::from_iter([("client.dll", buttons)])
        };

        super::formatter::write_pretty_json(fmt, &content)
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#![allow(non_upper_case_globals, unused)]\n")?;

        fmt.block("pub mod cs2_dumper", false, |fmt| {
            writeln!(fmt, "// Module: client.dll")?;

            fmt.block("pub mod buttons", false, |fmt| {
                let mut names = IdentifierAllocator::default();
                for (name, value) in self {
                    writeln!(
                        fmt,
                        "pub const {}: usize = {:#X};",
                        names.allocate(rust_identifier(name)),
                        value
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const cs2_dumper = struct", true, |fmt| {
            writeln!(fmt, "// Module: client.dll")?;

            fmt.block("pub const buttons = struct", true, |fmt| {
                let mut names = IdentifierAllocator::default();
                for (name, value) in self {
                    writeln!(
                        fmt,
                        "pub const {}: usize = {:#X};",
                        names.allocate(zig_ident(name).into_owned()),
                        value
                    )?;
                }

                Ok(())
            })
        })
    }
}
