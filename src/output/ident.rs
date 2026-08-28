//! Shared helpers for the new SDK-style emitters.
//!
//! These are intentionally tiny and dependency-free so the new emitter
//! files (`sdk_classes`, `netvars`, `interfaces_sdk`, `amalgamation`)
//! can share identifier-sanitisation logic without going through the
//! older `output::Formatter` machinery.

use std::borrow::Cow;
use std::collections::HashSet;

/// Allocate deterministic, unique identifiers within one generated scope.
#[derive(Default)]
pub(crate) struct IdentifierAllocator {
    used: HashSet<String>,
}

impl IdentifierAllocator {
    pub(crate) fn allocate(&mut self, base: impl Into<String>) -> String {
        let base = base.into();
        if self.used.insert(base.clone()) {
            return base;
        }
        for suffix in 2usize.. {
            let candidate = format!("{base}_{suffix}");
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
        }
        unreachable!("identifier suffix space exhausted")
    }
}

pub(crate) fn already_ascii_ident(input: &str) -> bool {
    !input.is_empty()
        && input
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// C++ keywords cannot be used for generated type, field, or enumerator
/// identifiers.  Keep this in the shared identifier module so every emitter
/// applies the same rule.
pub(crate) fn is_cpp_keyword(name: &str) -> bool {
    matches!(
        name,
        "alignas"
            | "alignof"
            | "and"
            | "and_eq"
            | "asm"
            | "auto"
            | "bitand"
            | "bitor"
            | "bool"
            | "break"
            | "case"
            | "catch"
            | "char"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "class"
            | "compl"
            | "const"
            | "constexpr"
            | "consteval"
            | "constinit"
            | "const_cast"
            | "continue"
            | "decltype"
            | "default"
            | "delete"
            | "do"
            | "double"
            | "dynamic_cast"
            | "else"
            | "enum"
            | "explicit"
            | "export"
            | "extern"
            | "false"
            | "float"
            | "for"
            | "friend"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "mutable"
            | "namespace"
            | "new"
            | "noexcept"
            | "not"
            | "not_eq"
            | "nullptr"
            | "operator"
            | "or"
            | "or_eq"
            | "private"
            | "protected"
            | "public"
            | "register"
            | "reinterpret_cast"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "static_assert"
            | "static_cast"
            | "struct"
            | "switch"
            | "template"
            | "this"
            | "thread_local"
            | "throw"
            | "true"
            | "try"
            | "typedef"
            | "typeid"
            | "typename"
            | "union"
            | "unsigned"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
            | "wchar_t"
            | "xor"
            | "xor_eq"
            | "co_await"
            | "co_return"
            | "co_yield"
            | "concept"
            | "requires"
    )
}

fn prefix_digit(input: &str) -> Cow<'_, str> {
    if input.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        let mut s = String::with_capacity(input.len() + 1);
        s.push('_');
        s.push_str(input);
        Cow::Owned(s)
    } else {
        Cow::Borrowed(input)
    }
}

fn rewrite_non_ident(input: &str) -> Cow<'static, str> {
    let mut s = String::with_capacity(input.len() + 1);
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        s.insert(0, '_');
    }
    Cow::Owned(s)
}

/// Replace anything that isn't `[A-Za-z0-9_]` with `_`. Used for module
/// names, file names, and namespace identifiers.
pub fn slugify(input: &str) -> Cow<'_, str> {
    if already_ascii_ident(input) {
        prefix_digit(input)
    } else {
        rewrite_non_ident(input)
    }
}

/// Like [`slugify`] but keeps the leading character if it's already a
/// valid C++ identifier start. Used for type names where we want
/// `C_CSPlayerPawn` to stay as `C_CSPlayerPawn`.
pub fn type_ident(input: &str) -> Cow<'_, str> {
    // Schema sometimes contains template-syntax names like
    // `CHandle< C_BaseEntity >`. For *type identifiers* in declarations
    // we strip everything from the first non-identifier character.
    let end = input
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(input.len());
    let ident = &input[..end];
    if ident.is_empty() {
        return Cow::Borrowed("anonymous");
    }
    prefix_digit(ident)
}

/// Turn an arbitrary symbol (e.g. a Pattern name like `Foo::Bar`) into a
/// usable C++/C# identifier by replacing every non-`[A-Za-z0-9_]` run with
/// `_`. Unlike [`type_ident`] this keeps the *whole* name (so `Foo::Bar`
/// becomes `Foo__Bar` rather than being truncated at `::`). Shared by the
/// vtable and interface-class emitters so a slot's index symbol and the
/// wrapper that references it always spell the same identifier.
pub fn sanitize_ident(raw: &str) -> Cow<'_, str> {
    slugify(raw)
}

/// Enumerator / field identifier for generated C++. Unlike [`cpp_type_ident`]
/// this does not collapse punctuation runs (`foo--bar` stays `foo__bar`) and
/// empty names become `_unnamed`.
pub fn sanitize_enum_member(raw: &str) -> Cow<'_, str> {
    if already_ascii_ident(raw)
        && !raw.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
        && !is_cpp_keyword(raw)
    {
        return Cow::Borrowed(raw);
    }
    let mut s = String::with_capacity(raw.len() + 2);
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            s.push(c);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() {
        s.push_str("_unnamed");
    }
    if s.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        s.insert(0, '_');
    }
    if is_cpp_keyword(&s) {
        s.insert(0, '_');
    }
    Cow::Owned(s)
}

/// C++ type / class identifier. Nested `::` names flatten to `_`, punctuation
/// runs collapse, keywords and leading digits are prefixed. Empty becomes
/// `Anonymous`. Used by both `sdk/` and include-tree emitters.
pub fn cpp_type_ident(raw: &str) -> Cow<'_, str> {
    if already_ascii_ident(raw)
        && !raw.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
        && !is_cpp_keyword(raw)
    {
        return Cow::Borrowed(raw);
    }
    Cow::Owned(rewrite_cpp_type_ident(raw))
}

fn rewrite_cpp_type_ident(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 1);
    let mut previous_separator = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
            previous_separator = false;
        } else if !previous_separator {
            out.push('_');
            previous_separator = true;
        }
    }
    if out.is_empty() {
        return "Anonymous".to_string();
    }
    if out.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        out.insert(0, '_');
    }
    if is_cpp_keyword(&out) {
        out.insert(0, '_');
    }
    out
}

fn language_identifier(raw: &str, reserved: impl Fn(&str) -> bool) -> String {
    let slug = slugify(raw);
    let base = if slug.is_empty() {
        "anonymous"
    } else {
        slug.as_ref()
    };
    if reserved(base) {
        format!("_{base}")
    } else {
        base.to_string()
    }
}

/// Make a schema name safe in generated C++ declarations.  Prefixing a
/// keyword keeps the original spelling recognizable while avoiding the
/// language's reserved namespace.
pub fn cpp_identifier(raw: &str) -> String {
    language_identifier(raw, is_cpp_keyword)
}

/// Make a schema name safe in generated Rust modules, types, and constants.
pub fn rust_identifier(raw: &str) -> String {
    language_identifier(raw, is_rust_keyword)
}

/// Make a schema name safe in generated C# declarations.  C# keywords are
/// prefixed instead of using `@` so the output remains usable in interpolated
/// and documentation contexts as well.
pub fn csharp_identifier(raw: &str) -> String {
    language_identifier(raw, is_csharp_keyword)
}

/// Identifier shared by emitters that produce matching C++ and C# symbols.
pub fn cpp_csharp_identifier(raw: &str) -> String {
    language_identifier(raw, |name| is_cpp_keyword(name) || is_csharp_keyword(name))
}

fn is_rust_keyword(name: &str) -> bool {
    matches!(
        name,
        "as"
            | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "gen"
            | "union"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "try"
    )
}

fn is_csharp_keyword(name: &str) -> bool {
    matches!(
        name,
        "abstract"
            | "as"
            | "base"
            | "bool"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "checked"
            | "class"
            | "const"
            | "continue"
            | "decimal"
            | "default"
            | "delegate"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "event"
            | "explicit"
            | "extern"
            | "false"
            | "finally"
            | "fixed"
            | "float"
            | "for"
            | "foreach"
            | "goto"
            | "if"
            | "implicit"
            | "in"
            | "int"
            | "interface"
            | "internal"
            | "is"
            | "lock"
            | "long"
            | "namespace"
            | "new"
            | "null"
            | "object"
            | "operator"
            | "out"
            | "override"
            | "params"
            | "private"
            | "protected"
            | "public"
            | "readonly"
            | "ref"
            | "return"
            | "sbyte"
            | "sealed"
            | "short"
            | "sizeof"
            | "stackalloc"
            | "static"
            | "string"
            | "struct"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "uint"
            | "ulong"
            | "unchecked"
            | "unsafe"
            | "ushort"
            | "using"
            | "virtual"
            | "void"
            | "volatile"
            | "while"
            | "add"
            | "alias"
            | "ascending"
            | "async"
            | "await"
            | "by"
            | "descending"
            | "dynamic"
            | "equals"
            | "file"
            | "from"
            | "global"
            | "group"
            | "init"
            | "into"
            | "join"
            | "let"
            | "managed"
            | "nameof"
            | "nint"
            | "not"
            | "notnull"
            | "nuint"
            | "on"
            | "orderby"
            | "partial"
            | "record"
            | "remove"
            | "required"
            | "select"
            | "scoped"
            | "set"
            | "unmanaged"
            | "value"
            | "var"
            | "when"
            | "where"
            | "with"
            | "yield"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        csharp_identifier, cpp_csharp_identifier, cpp_identifier, cpp_type_ident, is_cpp_keyword,
        rust_identifier, sanitize_enum_member, slugify, type_ident, IdentifierAllocator,
    };
    use std::borrow::Cow;

    #[test]
    fn slugify_borrows_clean_idents() {
        let name = "C_CSPlayerPawn";
        let out = slugify(name);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), name);
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
    }

    #[test]
    fn slugify_rewrites_punctuation() {
        assert_eq!(slugify("client.dll").as_ref(), "client_dll");
        assert_eq!(slugify("3d_type").as_ref(), "_3d_type");
    }

    #[test]
    fn type_ident_truncates_templates_without_copying_the_stem() {
        let raw = "CHandle< C_BaseEntity >";
        let out = type_ident(raw);
        assert_eq!(out.as_ref(), "CHandle");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), raw.as_ptr()));
    }

    #[test]
    fn recognizes_cpp_keywords() {
        assert!(is_cpp_keyword("class"));
        assert!(is_cpp_keyword("constexpr"));
        assert!(!is_cpp_keyword("C_BaseEntity"));
    }

    #[test]
    fn language_identifiers_escape_keywords_and_empty_names() {
        assert_eq!(cpp_identifier("class"), "_class");
        assert_eq!(rust_identifier("type"), "_type");
        assert_eq!(csharp_identifier("namespace"), "_namespace");
        assert_eq!(cpp_identifier(""), "anonymous");
        assert_eq!(rust_identifier("3d-value"), "_3d_value");
        assert_eq!(cpp_csharp_identifier("event"), "_event");
    }

    #[test]
    fn cpp_type_ident_flattens_nested_names_and_borrows_clean() {
        let name = "CCSPlayerPawn";
        let out = cpp_type_ident(name);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
        assert_eq!(
            cpp_type_ident("CPulseCell::TimelineEvent_t").as_ref(),
            "CPulseCell_TimelineEvent_t"
        );
        assert_eq!(cpp_type_ident("3d_type").as_ref(), "_3d_type");
        assert_eq!(cpp_type_ident("operator").as_ref(), "_operator");
        assert_eq!(cpp_type_ident("").as_ref(), "Anonymous");
    }

    #[test]
    fn sanitize_enum_member_keeps_punctuation_runs_and_empty_unnamed() {
        assert_eq!(sanitize_enum_member("class").as_ref(), "_class");
        assert_eq!(sanitize_enum_member("foo-bar").as_ref(), "foo_bar");
        assert_eq!(sanitize_enum_member("foo--bar").as_ref(), "foo__bar");
        assert_eq!(sanitize_enum_member("").as_ref(), "_unnamed");
        let name = "m_iHealth";
        let out = sanitize_enum_member(name);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
    }

    #[test]
    fn allocator_stably_disambiguates_sanitized_collisions() {
        let mut names = IdentifierAllocator::default();
        assert_eq!(names.allocate("foo_bar"), "foo_bar");
        assert_eq!(names.allocate("foo_bar"), "foo_bar_2");
        assert_eq!(names.allocate("foo_bar_2"), "foo_bar_2_2");
        assert_eq!(names.allocate("foo_bar"), "foo_bar_3");
    }
}
