//! Tipos de error del proxy Vetro.
//!
//! `ProxyError` cubre los fallos del path de evaluación AST. Los errores de
//! parsing se tratan de forma especial: una query que no parsea se bloquea por
//! precaución (fail-closed) y se reporta como `PARSE_ERROR`.

use thiserror::Error;

/// Límite de tamaño de query (64KB) impuesto por las coding standards.
pub const MAX_QUERY_SIZE_BYTES: usize = 64 * 1024;

/// Profundidad máxima del AST que se recorre (50 niveles).
pub const MAX_AST_DEPTH: usize = 50;

#[derive(Debug, Error)]
pub enum ProxyError {
    /// La query SQL tiene sintaxis inválida o malformada.
    /// Código de cara al cliente: `VETRO-PARSE-ERROR`.
    #[error("VETRO-PARSE-ERROR: {0}")]
    ParseError(String),

    /// La query excede el tamaño máximo permitido (64KB).
    #[error("VETRO-QUERY-TOO-LARGE: la query excede el límite de {MAX_QUERY_SIZE_BYTES} bytes")]
    QueryTooLarge,

    /// El AST excede la profundidad máxima de anidamiento (50 niveles).
    /// Posible intento de evasión por anidamiento excesivo.
    #[error("VETRO-AST-TOO-DEEP: el AST excede la profundidad máxima de {MAX_AST_DEPTH} niveles")]
    AstTooDeep,

    /// Dialecto no soportado.
    #[error("VETRO-UNSUPPORTED-DIALECT: dialecto '{0}' no soportado")]
    UnsupportedDialect(String),

    /// Una regla custom YAML está malformada.
    #[error("VETRO-INVALID-RULE: regla custom inválida: {0}")]
    InvalidCustomRule(String),
}

pub type Result<T> = std::result::Result<T, ProxyError>;
