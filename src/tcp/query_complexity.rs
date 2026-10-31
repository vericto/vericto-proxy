// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Linear-time lexical guard in front of the SQL parsers.
//!
//! A long left-associative expression (`1 + 1 + …`) can make an otherwise
//! bounded statement quadratic in a parser before the engine's AST-depth guard
//! gets a tree to inspect. This scanner counts operator tokens in each
//! unparenthesized expression segment and stops as soon as one exceeds the
//! configured ceiling. It does not build tokens or an AST, and it allocates
//! only after 32 simultaneously open parentheses.
//!
//! This is deliberately a lexical admission check, not a SQL rule. Text inside
//! literals, quoted identifiers and ordinary comments does not count. MySQL
//! executable comments (`/*! … */`) do count because the server and sqlparser
//! read their contents as SQL. MySQL is scanned under both backslash-escape
//! readings, matching the engine's treatment of `NO_BACKSLASH_ESCAPES`.

use std::fmt;

use vericto_engine::Dialect;

/// Prefix of the parse-error message emitted by this guard. Recognizing a
/// refusal takes the whole message, not this prefix: see
/// [`TooManyBinaryOperators::from_message`].
pub const BINARY_OPERATOR_ERROR_PREFIX: &str = "lexical complexity guard:";

/// Stand-in reported for text refused before parsing. As with an oversized
/// statement, it was never safe to sanitize, so only its size leaves the proxy.
pub fn refusal_marker(bytes: usize) -> String {
    format!("<query of {bytes} bytes refused by lexical complexity guard; text not reported>")
}

/// More operators than this in one unparenthesized expression are refused
/// before parsing. Configurable with `VERICTO_MAX_BINARY_OPERATORS`.
pub const DEFAULT_MAX_BINARY_OPERATORS: usize = 10_000;

/// A lexical expression exceeded [`DEFAULT_MAX_BINARY_OPERATORS`] or the
/// operator's configured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyBinaryOperators {
    pub seen: usize,
    pub limit: usize,
}

impl fmt::Display for TooManyBinaryOperators {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} more than {} binary operators in one unparenthesized expression (saw at least {}); raise VERICTO_MAX_BINARY_OPERATORS only for reviewed SQL",
            BINARY_OPERATOR_ERROR_PREFIX, self.limit, self.seen
        )
    }
}

impl TooManyBinaryOperators {
    /// The refusal `message` is, when it is exactly this guard's own message as
    /// [`fmt::Display`] writes it, and `None` for any other text.
    ///
    /// The message is the only trace of a refusal on a decision, so it is
    /// matched as the serialization of this type, not by a substring: a parser
    /// error can quote the client's tokens, and a statement that merely spells
    /// the prefix must still be reported as the parse error it is. The engine's
    /// own parse errors start with their `VERICTO-` code, so none can equal it.
    pub fn from_message(message: &str) -> Option<Self> {
        let digits = |s: &str| -> Option<usize> {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            s.parse().ok()
        };
        let rest = message
            .strip_prefix(BINARY_OPERATOR_ERROR_PREFIX)?
            .strip_prefix(" more than ")?;
        let (limit, rest) = rest.split_once(' ')?;
        let rest =
            rest.strip_prefix("binary operators in one unparenthesized expression (saw at least ")?;
        let (seen, _) = rest.split_once(')')?;
        let refusal = Self {
            seen: digits(seen)?,
            limit: digits(limit)?,
        };
        (refusal.to_string() == message).then_some(refusal)
    }
}

/// Refuses a binary-operator chain above `limit`.
///
/// `limit` is inclusive: exactly that many operators is accepted. Runtime
/// configuration never supplies zero; treating it literally here keeps the
/// pure function unsurprising and makes its boundary directly testable.
pub fn check_binary_operator_chains(
    sql: &str,
    dialect: Dialect,
    limit: usize,
) -> Result<(), TooManyBinaryOperators> {
    // Every operator consumes at least one byte. A statement no longer than the
    // threshold cannot possibly exceed it, so ordinary traffic pays one length
    // comparison and no lexical pass.
    if sql.len() <= limit {
        return Ok(());
    }
    match dialect {
        Dialect::Mysql => {
            // The server can change NO_BACKSLASH_ESCAPES per session, while the
            // proxy cannot observe every way it is set. Neither reading may
            // hide a chain from the guard. Without a backslash the readings are
            // identical, so scanning twice would only charge normal traffic.
            scan(sql, dialect, limit, true)?;
            if sql.as_bytes().contains(&b'\\') {
                scan(sql, dialect, limit, false)
            } else {
                Ok(())
            }
        }
        _ => scan(sql, dialect, limit, false),
    }
}

fn scan(
    sql: &str,
    dialect: Dialect,
    limit: usize,
    mysql_backslash_escapes: bool,
) -> Result<(), TooManyBinaryOperators> {
    let bytes = sql.as_bytes();
    let mut i = 0;
    // The normal path stays allocation-free through 32 open parentheses; only
    // more deeply nested input needs the overflow vector. Commas start another
    // expression at the current depth. Closing a parenthesis resumes the outer
    // parenthesis resumes the outer expression, so `(a)+(b)+(c)` counts its two
    // outer `+`s.
    let mut parents = [0usize; 32];
    let mut overflow = Vec::new();
    let mut depth = 0usize;
    let mut chain = 0usize;
    let mut executable_comment = false;

    while i < bytes.len() {
        if executable_comment && starts(bytes, i, b"*/") {
            executable_comment = false;
            i += 2;
            continue;
        }

        // Comments must be recognized before `/`, `*`, `-` and `#` operators.
        if starts(bytes, i, b"/*") {
            if dialect == Dialect::Mysql && bytes.get(i + 2) == Some(&b'!') {
                // MySQL executes this body (subject to an optional version
                // prefix); count it as code and discard only the delimiters.
                executable_comment = true;
                i += 3;
                continue;
            }
            i = skip_block_comment(bytes, i + 2, dialect == Dialect::Postgres);
            continue;
        }
        if starts(bytes, i, b"--") && is_dash_comment(bytes, i, dialect) {
            i = skip_line(bytes, i + 2);
            continue;
        }
        if dialect == Dialect::Mysql && bytes[i] == b'#' {
            i = skip_line(bytes, i + 1);
            continue;
        }

        match bytes[i] {
            b'\'' => {
                let backslash = match dialect {
                    Dialect::Mysql => mysql_backslash_escapes,
                    Dialect::Postgres => postgres_escape_string_prefix(bytes, i),
                    _ => false,
                };
                i = skip_quoted(bytes, i + 1, b'\'', backslash);
            }
            b'"' => {
                i = skip_quoted(
                    bytes,
                    i + 1,
                    b'"',
                    dialect == Dialect::Mysql && mysql_backslash_escapes,
                );
            }
            b'`' => {
                i = skip_quoted(
                    bytes,
                    i + 1,
                    b'`',
                    dialect == Dialect::Mysql && mysql_backslash_escapes,
                );
            }
            b'[' if dialect == Dialect::MsSql => {
                i = skip_bracket_identifier(bytes, i + 1);
            }
            b'$' if dialect == Dialect::Postgres => {
                if let Some(end) = skip_dollar_quote(sql, i) {
                    i = end;
                } else {
                    i += 1;
                }
            }
            b'(' => {
                if depth < parents.len() {
                    parents[depth] = chain;
                } else {
                    overflow.push(chain);
                }
                depth += 1;
                chain = 0;
                i += 1;
            }
            b')' => {
                if depth > 0 {
                    depth -= 1;
                    chain = if depth < parents.len() {
                        parents[depth]
                    } else {
                        overflow.pop().unwrap_or(0)
                    };
                }
                i += 1;
            }
            b',' => {
                chain = 0;
                i += 1;
            }
            b';' => {
                depth = 0;
                chain = 0;
                overflow.clear();
                i += 1;
            }
            b if is_ident_start(b) => {
                let start = i;
                i += 1;
                while i < bytes.len() && is_ident_continue(bytes[i]) {
                    i += 1;
                }
                let word = &bytes[start..i];
                if is_word_operator(word) {
                    record(&mut chain, limit)?;
                }
            }
            b if is_operator_char(b, dialect) => {
                i += 1;
                while i < bytes.len() && is_operator_char(bytes[i], dialect) {
                    // Do not swallow a comment opener into an operator token.
                    if starts(bytes, i, b"/*")
                        || (starts(bytes, i, b"--") && is_dash_comment(bytes, i, dialect))
                    {
                        break;
                    }
                    i += 1;
                }
                record(&mut chain, limit)?;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

fn record(count: &mut usize, limit: usize) -> Result<(), TooManyBinaryOperators> {
    *count = count.saturating_add(1);
    if *count > limit {
        Err(TooManyBinaryOperators {
            seen: *count,
            limit,
        })
    } else {
        Ok(())
    }
}

fn starts(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    bytes.get(at..at.saturating_add(needle.len())) == Some(needle)
}

fn skip_line(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && !matches!(bytes[i], b'\n' | b'\r') {
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], mut i: usize, nested: bool) -> usize {
    let mut depth = 1usize;
    while i < bytes.len() {
        if nested && starts(bytes, i, b"/*") {
            depth = depth.saturating_add(1);
            i += 2;
        } else if starts(bytes, i, b"*/") {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn is_dash_comment(bytes: &[u8], at: usize, dialect: Dialect) -> bool {
    dialect != Dialect::Mysql
        || bytes
            .get(at + 2)
            .is_none_or(|b| b.is_ascii_whitespace() || *b < 0x20)
}

fn postgres_escape_string_prefix(bytes: &[u8], quote: usize) -> bool {
    if quote >= 1
        && matches!(bytes[quote - 1], b'e' | b'E')
        && (quote == 1 || !is_ident_continue(bytes[quote - 2]))
    {
        return true;
    }
    quote >= 2
        && bytes[quote - 2].eq_ignore_ascii_case(&b'u')
        && bytes[quote - 1] == b'&'
        && (quote == 2 || !is_ident_continue(bytes[quote - 3]))
}

fn skip_quoted(bytes: &[u8], mut i: usize, quote: u8, backslash: bool) -> usize {
    while i < bytes.len() {
        if backslash && bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return i + 1;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn skip_bracket_identifier(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b']' {
            if bytes.get(i + 1) == Some(&b']') {
                i += 2;
            } else {
                return i + 1;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn skip_dollar_quote(sql: &str, at: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let mut end = at + 1;
    if bytes.get(end) == Some(&b'$') {
        end += 1;
    } else {
        let first = *bytes.get(end)?;
        if !(is_ident_start(first) || first >= 0x80) {
            return None;
        }
        end += 1;
        while bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b >= 0x80)
        {
            end += 1;
        }
        if bytes.get(end) != Some(&b'$') {
            return None;
        }
        end += 1;
    }
    let delimiter = &sql[at..end];
    Some(
        sql[end..]
            .find(delimiter)
            .map_or(sql.len(), |n| end + n + delimiter.len()),
    )
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$') || b >= 0x80
}

fn is_operator_char(b: u8, dialect: Dialect) -> bool {
    // `?` is a MySQL bind parameter and `#` starts a MySQL comment; both can be
    // PostgreSQL operators.
    matches!(
        b,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'='
            | b'<'
            | b'>'
            | b'!'
            | b'~'
            | b'^'
            | b'&'
            | b'|'
            | b':'
            | b'@'
    ) || (matches!(b, b'?' | b'#') && dialect != Dialect::Mysql)
}

fn is_word_operator(word: &[u8]) -> bool {
    [
        b"and".as_slice(),
        b"or",
        b"xor",
        b"div",
        b"mod",
        b"like",
        b"ilike",
        b"rlike",
        b"regexp",
        b"similar",
        b"is",
        b"in",
        b"between",
        b"overlaps",
        // PostgreSQL's qualified-operator syntax and `AT TIME ZONE` are
        // operators even though their spelling contains words/parentheses.
        b"operator",
        b"at",
    ]
    .iter()
    .any(|operator| word.eq_ignore_ascii_case(operator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(sql: &str, dialect: Dialect, limit: usize) -> bool {
        check_binary_operator_chains(sql, dialect, limit).is_ok()
    }

    #[test]
    fn the_limit_is_inclusive_and_stops_one_operator_later() {
        assert!(check("SELECT 1+1+1", Dialect::Postgres, 2));
        let err = check_binary_operator_chains("SELECT 1+1+1+1", Dialect::Postgres, 2).unwrap_err();
        assert_eq!(err.seen, 3);
        assert_eq!(err.limit, 2);
        assert!(err.to_string().contains("VERICTO_MAX_BINARY_OPERATORS"));
    }

    #[test]
    fn only_the_guards_exact_message_reads_back_as_a_refusal() {
        let refusal = TooManyBinaryOperators {
            seen: 10_001,
            limit: 10_000,
        };
        assert_eq!(
            TooManyBinaryOperators::from_message(&refusal.to_string()),
            Some(refusal)
        );
        let exact = refusal.to_string();
        for other in [
            String::new(),
            BINARY_OPERATOR_ERROR_PREFIX.to_string(),
            format!("VERICTO-PARSE-ERROR: found: {exact}"),
            format!("{exact} "),
            format!("{exact}; and more"),
            exact.replace("10000", "+10000"),
            exact.replace("10001", ""),
        ] {
            assert_eq!(
                TooManyBinaryOperators::from_message(&other),
                None,
                "{other}"
            );
        }
    }

    #[test]
    fn parentheses_and_commas_isolate_expression_chains() {
        assert!(check(
            "SELECT (1+1+1), (2+2+2), (3+3+3)",
            Dialect::Postgres,
            2
        ));
        assert!(check("SELECT (1)+(2)+(3)", Dialect::Postgres, 2));
        assert!(!check("SELECT (1)+(2)+(3)+(4)", Dialect::Postgres, 2));

        let nested = format!("SELECT 1 + {}1{} + 2", "(".repeat(40), ")".repeat(40));
        assert!(check(&nested, Dialect::Postgres, 2));
        assert!(!check(&nested, Dialect::Postgres, 1));
    }

    #[test]
    fn comments_literals_and_identifiers_do_not_count() {
        let many = "+".repeat(64);
        let pg = format!(
            "SELECT '{many}', E'\\\\{many}', \"{many}\", $tag${many}$tag$ /* {many} /* {many} */ */ -- {many}\n1"
        );
        assert!(check(&pg, Dialect::Postgres, 0), "{pg}");

        let mysql = format!("SELECT '{many}', \"{many}\", `{many}` /* {many} */ # {many}\n1");
        assert!(check(&mysql, Dialect::Mysql, 0), "{mysql}");
    }

    #[test]
    fn postgres_non_ascii_dollar_tags_are_literals() {
        let operators = "+".repeat(64);
        let sql = format!("DO $é${operators}$é$");
        assert!(check(&sql, Dialect::Postgres, 0), "{sql}");
    }

    #[test]
    fn one_unterminated_dollar_quote_consumes_the_remaining_tail() {
        let sql = format!(
            "SELECT {}",
            (0..40_000)
                .map(|i| format!("$tag{i}$"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert!(sql.len() > 300_000);
        assert!(check(&sql, Dialect::Postgres, 0));
    }

    #[test]
    fn mysql_executable_comments_are_code() {
        assert!(!check("SELECT 1 /*! + 1 + 1 */", Dialect::Mysql, 1));
        assert!(check("SELECT 1 /* + 1 + 1 */", Dialect::Mysql, 0));
    }

    #[test]
    fn mysql_question_marks_are_operands_not_operators() {
        assert!(check("SELECT ? + ? + ?", Dialect::Mysql, 2));
        assert!(!check("SELECT ? + ? + ?", Dialect::Mysql, 1));
    }

    #[test]
    fn logical_and_qualified_operators_count() {
        assert!(!check(
            "SELECT 1 WHERE a = 1 OR b LIKE 'x' AND c IS NULL",
            Dialect::Postgres,
            4
        ));
        assert!(!check(
            "SELECT 1 OPERATOR(pg_catalog.+) 1 OPERATOR(pg_catalog.+) 1",
            Dialect::Postgres,
            1
        ));
        assert!(!check(
            "SELECT now() AT TIME ZONE 'UTC' AT TIME ZONE 'UTC'",
            Dialect::Postgres,
            1
        ));
    }

    #[test]
    fn expression_valid_keywords_never_reset_the_chain() {
        let sql = format!(
            "SELECT 0{}",
            " + LEFT('x', 1)".repeat(DEFAULT_MAX_BINARY_OPERATORS + 1)
        );
        for dialect in [Dialect::Postgres, Dialect::Mysql] {
            let err = check_binary_operator_chains(&sql, dialect, DEFAULT_MAX_BINARY_OPERATORS)
                .unwrap_err();
            assert_eq!(err.seen, DEFAULT_MAX_BINARY_OPERATORS + 1, "{dialect:?}");
        }
        assert!(check(
            "SELECT 1 LEFT JOIN t ON t.id = 1",
            Dialect::Postgres,
            2
        ));
    }

    #[test]
    fn mysql_dash_comment_follows_mysqls_whitespace_rule() {
        assert!(check("SELECT 1 -- + +\n", Dialect::Mysql, 0));
        assert!(!check("SELECT 1 --x", Dialect::Mysql, 0));
    }

    #[test]
    fn a_one_mib_adversarial_tail_stops_at_the_first_excess() {
        let sql = format!("SELECT {}1", "1+".repeat(512 * 1024));
        assert!(sql.len() >= 1024 * 1024);
        let err =
            check_binary_operator_chains(&sql, Dialect::Postgres, DEFAULT_MAX_BINARY_OPERATORS)
                .unwrap_err();
        assert_eq!(err.seen, DEFAULT_MAX_BINARY_OPERATORS + 1);
    }

    #[test]
    fn a_wide_values_batch_does_not_combine_independent_rows() {
        let sql = format!(
            "INSERT INTO t (id, delta, note) VALUES {}",
            (0..12_000)
                .map(|i| format!("({i}, -1, '+ not an operator')"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(sql.len() > 256 * 1024);
        assert!(check(&sql, Dialect::Postgres, 1));
    }
}
