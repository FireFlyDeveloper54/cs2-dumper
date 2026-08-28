use std::fmt::{self, Write};

use serde::Serialize;

pub fn pretty_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value)
}

/// Serialize `value` as pretty JSON into `fmt`. A serde failure is a write
/// error (`fmt::Error`), not a panic.
pub fn write_pretty_json<T: Serialize>(fmt: &mut Formatter<'_>, value: &T) -> fmt::Result {
    let json = pretty_json(value).map_err(|_| fmt::Error)?;
    fmt.write_str(&json)
}

pub struct Formatter<'a> {
    out: &'a mut String,
    indent_size: usize,
    indent_level: usize,
}

impl<'a> Formatter<'a> {
    pub fn new(out: &'a mut String, indent_size: usize) -> Self {
        Self {
            out,
            indent_size,
            indent_level: 0,
        }
    }

    pub fn block<H, F>(&mut self, heading: H, semicolon: bool, f: F) -> fmt::Result
    where
        H: fmt::Display,
        F: FnOnce(&mut Self) -> fmt::Result,
    {
        writeln!(self, "{heading} {{")?;

        self.indent(f)?;

        writeln!(self, "{}", if semicolon { "};" } else { "}" })?;

        Ok(())
    }

    pub fn indent<F>(&mut self, f: F) -> fmt::Result
    where
        F: FnOnce(&mut Self) -> fmt::Result,
    {
        self.indent_level += 1;
        let result = f(self);
        self.indent_level -= 1;
        result
    }

    #[inline]
    fn push_indentation(&mut self) {
        let n = self.indent_level.saturating_mul(self.indent_size);
        if n == 0 {
            return;
        }
        const SPACES: &str = "                                                                ";
        if n <= SPACES.len() {
            self.out.push_str(&SPACES[..n]);
        } else {
            self.out.extend(std::iter::repeat_n(' ', n));
        }
    }
}

impl<'a> Write for Formatter<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut lines = s.lines().peekable();

        while let Some(line) = lines.next() {
            if self.out.ends_with('\n') && !line.is_empty() {
                self.push_indentation();
            }

            self.out.push_str(line);

            if lines.peek().is_some() || s.ends_with('\n') {
                self.out.push('\n');
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Formatter;
    use std::fmt;
    use std::fmt::Write;

    #[test]
    fn indents_nested_block_without_per_line_repeat_alloc() {
        let mut out = String::new();
        let mut fmt = Formatter::new(&mut out, 4);
        fmt.block("namespace test", false, |fmt| writeln!(fmt, "int x;"))
            .unwrap();
        assert!(out.contains("    int x;"), "{out}");
        assert!(out.contains("namespace test {"), "{out}");
        assert!(out.contains('}'), "{out}");
    }

    #[test]
    fn indent_level_is_restored_when_writer_fails() {
        let mut out = String::new();
        let mut fmt = Formatter::new(&mut out, 4);
        assert!(fmt.indent(|_| Err(fmt::Error)).is_err());
        writeln!(&mut fmt, "after").unwrap();
        assert_eq!(out, "after\n");
    }
}
