use std::collections::BTreeMap;
use std::fmt::{self, Write};

use heck::{AsPascalCase, AsSnakeCase};

use super::ident::{
    csharp_identifier, cpp_identifier, rust_identifier, IdentifierAllocator,
};
use super::{comment_text, slugify, zig_ident, CodeWriter, Formatter, InterfaceMap};

impl CodeWriter for InterfaceMap {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("namespace CS2Dumper.Interfaces", false, |fmt| {
            let mut modules = IdentifierAllocator::default();
            for (module_name, ifaces) in self {
                writeln!(fmt, "// Module: {}", comment_text(module_name))?;
                let module_ident = modules.allocate(
                    AsPascalCase(csharp_identifier(module_name)).to_string(),
                );

                fmt.block(
                    format_args!("public static class {module_ident}"),
                    false,
                    |fmt| {
                        let mut names = IdentifierAllocator::default();
                        for (name, value) in ifaces {
                            if *value > i32::MAX as u64 {
                                writeln!(
                                    fmt,
                                    "public static readonly nint {} = unchecked((nint){:#X});",
                                    names.allocate(csharp_identifier(name)),
                                    value
                                )?;
                            } else {
                                writeln!(
                                    fmt,
                                    "public const nint {} = {:#X};",
                                    names.allocate(csharp_identifier(name)),
                                    value
                                )?;
                            };
                        }

                        Ok(())
                    },
                )?;
            }

            Ok(())
        })
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#pragma once\n")?;
        writeln!(fmt, "#include <cstddef>")?;
        writeln!(fmt, "#include <cstdint>\n")?;

        fmt.block("namespace cs2_dumper", false, |fmt| {
            fmt.block("namespace interfaces", false, |fmt| {
                let mut modules = IdentifierAllocator::default();
                for (module_name, ifaces) in self {
                    writeln!(fmt, "// Module: {}", comment_text(module_name))?;
                    let module_ident = modules.allocate(cpp_identifier(
                        &AsSnakeCase(slugify(module_name)).to_string(),
                    ));

                    fmt.block(
                        format_args!("namespace {module_ident}"),
                        false,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            for (name, value) in ifaces {
                                writeln!(
                                    fmt,
                                    "constexpr std::ptrdiff_t {} = {:#X};",
                                    names.allocate(cpp_identifier(name)),
                                    value
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        let content: BTreeMap<_, _> = self
            .iter()
            .map(|(module_name, ifaces)| {
                let ifaces: BTreeMap<_, _> = ifaces.iter().collect();

                (module_name, ifaces)
            })
            .collect();

        super::formatter::write_pretty_json(fmt, &content)
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        writeln!(fmt, "#![allow(non_upper_case_globals, unused)]\n")?;

        fmt.block("pub mod cs2_dumper", false, |fmt| {
            fmt.block("pub mod interfaces", false, |fmt| {
                let mut modules = IdentifierAllocator::default();
                for (module_name, ifaces) in self {
                    writeln!(fmt, "// Module: {}", comment_text(module_name))?;
                    let module_ident = modules.allocate(rust_identifier(
                        &AsSnakeCase(slugify(module_name)).to_string(),
                    ));

                    fmt.block(
                        format_args!("pub mod {module_ident}"),
                        false,
                        |fmt| {
                            let mut names = IdentifierAllocator::default();
                            for (name, value) in ifaces {
                                writeln!(
                                    fmt,
                                    "pub const {}: usize = {:#X};",
                                    names.allocate(rust_identifier(name)),
                                    value
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        fmt.block("pub const cs2_dumper = struct", true, |fmt| {
            fmt.block("pub const interfaces = struct", true, |fmt| {
                for (module_name, ifaces) in self {
                    writeln!(fmt, "// Module: {}", comment_text(module_name))?;

                    let snake = AsSnakeCase(slugify(module_name).as_ref()).to_string();
                    let module_name = zig_ident(&snake);

                    fmt.block(
                        format_args!("pub const {} = struct", module_name),
                        true,
                        |fmt| {
                            for (name, value) in ifaces {
                                writeln!(
                                    fmt,
                                    "pub const {}: usize = {:#X};",
                                    zig_ident(name),
                                    value
                                )?;
                            }

                            Ok(())
                        },
                    )?;
                }

                Ok(())
            })
        })
    }
}
