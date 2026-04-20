//! CLI command implementations.

pub mod add;
pub(crate) mod codegen;
pub mod dev;
pub mod doctor;
#[cfg(feature = "import")]
pub mod import;
pub mod jobs;
pub mod migrate;
pub mod new;
pub mod openapi;
pub mod routes;
#[cfg(feature = "seed")]
pub mod seed;
pub mod templates;
pub mod test;

#[cfg(feature = "import-openapi")]
pub mod import_openapi;
pub(crate) use colored::Colorize;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NormalizedType {
    String,
    Text,
    I32,
    I64,
    F32,
    F64,
    Bool,
    Uuid,
    DateTimeUtc,
    DateTime,
    Date,
    Decimal,
    Json,
    Bytes,
    Time,
    #[cfg(feature = "import")]
    Unmappable(String),
}

impl std::str::FromStr for NormalizedType {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "string" | "str" => Ok(NormalizedType::String),
            "text" => Ok(NormalizedType::Text),
            "i32" | "integer" | "int" => Ok(NormalizedType::I32),
            "i64" | "bigint" => Ok(NormalizedType::I64),
            "f32" | "float" => Ok(NormalizedType::F32),
            "f64" | "double" => Ok(NormalizedType::F64),
            "bool" | "boolean" => Ok(NormalizedType::Bool),
            "uuid" => Ok(NormalizedType::Uuid),
            "datetimeutc" | "datetime" | "timestamptz" => Ok(NormalizedType::DateTimeUtc),
            "naivedatetime" | "timestamp" => Ok(NormalizedType::DateTime),
            "date" => Ok(NormalizedType::Date),
            "decimal" | "numeric" | "money" => Ok(NormalizedType::Decimal),
            "json" | "jsonb" => Ok(NormalizedType::Json),
            "bytes" | "blob" | "binary" | "bytea" | "varbinary" => Ok(NormalizedType::Bytes),
            "time" => Ok(NormalizedType::Time),
            _ => Err(format!("Unknown field type '{}'", value)),
        }
    }
}

impl std::fmt::Display for NormalizedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            NormalizedType::String | NormalizedType::Text => "String",
            NormalizedType::I32 => "i32",
            NormalizedType::I64 => "i64",
            NormalizedType::F32 => "f32",
            NormalizedType::F64 => "f64",
            NormalizedType::Bool => "bool",
            NormalizedType::Uuid => "Uuid",
            NormalizedType::DateTimeUtc => "DateTimeUtc",
            NormalizedType::DateTime => "DateTime",
            NormalizedType::Date => "Date",
            NormalizedType::Decimal => "Decimal",
            NormalizedType::Json => "Json",
            NormalizedType::Bytes => "Vec<u8>",
            NormalizedType::Time => "Time",
            #[cfg(feature = "import")]
            NormalizedType::Unmappable(s) => s,
        };
        write!(f, "{}", s)
    }
}

impl NormalizedType {
    pub(crate) fn schema_type_name(&self) -> String {
        match self {
            NormalizedType::String => "String".to_string(),
            NormalizedType::Text => "Text".to_string(),
            NormalizedType::I32 => "i32".to_string(),
            NormalizedType::I64 => "i64".to_string(),
            NormalizedType::F32 => "f32".to_string(),
            NormalizedType::F64 => "f64".to_string(),
            NormalizedType::Bool => "bool".to_string(),
            NormalizedType::Uuid => "Uuid".to_string(),
            NormalizedType::DateTimeUtc => "DateTime".to_string(),
            NormalizedType::DateTime => "NaiveDateTime".to_string(),
            NormalizedType::Date => "Date".to_string(),
            NormalizedType::Decimal => "Decimal".to_string(),
            NormalizedType::Json => "Json".to_string(),
            NormalizedType::Bytes => "Vec<u8>".to_string(),
            NormalizedType::Time => "Time".to_string(),
            #[cfg(feature = "import")]
            NormalizedType::Unmappable(s) => s.clone(),
        }
    }

    pub(crate) fn sea_orm_import_name(&self) -> Option<&'static str> {
        match self {
            NormalizedType::DateTimeUtc => Some("DateTimeUtc"),
            NormalizedType::DateTime => Some("DateTime"),
            NormalizedType::Date => Some("Date"),
            NormalizedType::Json => Some("Json"),
            NormalizedType::Time => Some("Time"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ColumnMethod(String);

impl std::fmt::Display for ColumnMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ColumnMethod {
    fn not_null(&self) -> Self {
        ColumnMethod(format!("{}.not_null()", self.0))
    }

    pub(crate) fn new(normalized_type: &NormalizedType, nullable: bool) -> Self {
        let base = match normalized_type {
            NormalizedType::String => ".string()",
            NormalizedType::Text => ".text()",
            NormalizedType::I32 => ".integer()",
            NormalizedType::I64 => ".big_integer()",
            NormalizedType::F32 => ".float()",
            NormalizedType::F64 => ".double()",
            NormalizedType::Bool => ".boolean()",
            NormalizedType::Uuid => ".uuid()",
            NormalizedType::DateTimeUtc => ".timestamp_with_time_zone()",
            NormalizedType::DateTime => ".date_time()",
            NormalizedType::Date => ".date()",
            NormalizedType::Decimal => ".decimal()",
            NormalizedType::Json => ".json()",
            NormalizedType::Bytes => ".binary()",
            NormalizedType::Time => ".time()",
            #[cfg(feature = "import")]
            NormalizedType::Unmappable(_) => "",
        };

        let column_method = ColumnMethod(base.to_string());

        if nullable || base.is_empty() {
            return column_method;
        }

        column_method.not_null()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FieldInfo {
    pub name: String,
    pub normalized_type: NormalizedType,
    pub column_method: ColumnMethod,
    pub nullable: bool,
}

impl std::str::FromStr for FieldInfo {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = value.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid field format: '{}'. Expected 'name:type'",
                value
            ));
        }

        let name = parts[0].to_string();

        ValidationContext::Field.validate(&name)?;

        let normalized_type = parts[1].parse::<NormalizedType>()?;
        let nullable = false;
        let column_method = ColumnMethod::new(&normalized_type, nullable);
        Ok(FieldInfo {
            name,
            normalized_type,
            column_method,
            nullable,
        })
    }
}

pub(crate) enum ValidationContext {
    Field,
    Resource,
}

impl ValidationContext {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Field => "Field name",
            Self::Resource => "Resource name",
        }
    }

    pub(crate) fn validate(&self, name: &str) -> Result<(), String> {
        let ctx_prefix = self.as_str();

        if name.is_empty() {
            return Err(format!("{} cannot be empty", ctx_prefix));
        }

        if name.chars().next().unwrap().is_ascii_digit() {
            return Err(format!("{} cannot start with a digit", ctx_prefix));
        }

        if let Some(c) = name
            .chars()
            .find(|&c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '_')
        {
            return Err(format!(
                "{} must be lowercase alphanumeric with underscores, got '{}'",
                ctx_prefix, c
            ));
        }

        if name.starts_with('_') || name.ends_with('_') {
            return Err(format!(
                "{} cannot start or end with underscore",
                ctx_prefix
            ));
        }

        let reserved = [
            "self", "super", "crate", "mod", "type", "fn", "struct", "enum", "impl",
        ];
        if reserved.contains(&name) {
            return Err(format!(
                "'{}' is a reserved Rust keyword and cannot be used as a {}",
                name,
                ctx_prefix.to_lowercase()
            ));
        }

        Ok(())
    }
}

/// Verify that we're in a valid Rapina project directory.
pub fn verify_rapina_project() -> Result<toml::Value, String> {
    let cargo_toml = std::path::Path::new("Cargo.toml");
    if !cargo_toml.exists() {
        return Err("No Cargo.toml found. Are you in a Rust project directory?".to_string());
    }

    let content = std::fs::read_to_string(cargo_toml)
        .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?;

    let parsed: toml::Value =
        toml::from_str(&content).map_err(|e| format!("Failed to parse Cargo.toml: {}", e))?;

    // Check for rapina in dependencies
    let has_rapina = parsed
        .get("dependencies")
        .and_then(|deps| deps.get("rapina"))
        .is_some();

    if !has_rapina {
        return Err(
            "This doesn't appear to be a Rapina project (no rapina dependency found)".to_string(),
        );
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use crate::commands::ValidationContext;

    use super::{ColumnMethod, FieldInfo, NormalizedType};

    #[test]
    fn test_parse_field_valid() {
        let field: FieldInfo = "name:string".parse().unwrap();
        assert_eq!(field.name, "name");
        assert_eq!(field.normalized_type, NormalizedType::String);
        assert_eq!(
            field.column_method,
            ColumnMethod(".string().not_null()".to_string())
        );
        assert!(!field.nullable);
    }

    #[test]
    fn test_parse_field_invalid() {
        let field: Result<FieldInfo, String> = "name".parse();
        assert!(field.is_err());
    }

    #[test]
    fn test_parse_field_invalid_type() {
        let field: Result<FieldInfo, String> = "name:invalid".parse();
        assert!(field.is_err());
    }

    #[test]
    fn test_parse_field_invalid_name() {
        let field: Result<FieldInfo, String> = "_name:string".parse();
        assert!(field.is_err());
    }

    #[test]
    fn test_parse_field_invalid_name_empty() {
        let field: Result<FieldInfo, String> = ":string".parse();
        assert!(field.is_err());
    }

    #[test]
    fn test_parse_field_valid_nullable() {
        let field: FieldInfo = "name:string".parse().unwrap();
        assert_eq!(field.name, "name");
        assert_eq!(field.normalized_type, NormalizedType::String);
        assert_eq!(
            field.column_method,
            ColumnMethod(".string().not_null()".to_string())
        );
        assert!(!field.nullable);
    }

    #[test]
    fn test_validate_resource_name_valid() {
        assert!(ValidationContext::Resource.validate("user").is_ok());
        assert!(ValidationContext::Resource.validate("blog_post").is_ok());
        assert!(ValidationContext::Resource.validate("item123").is_ok());
    }

    #[test]
    fn test_validate_resource_name_invalid() {
        assert!(ValidationContext::Resource.validate("").is_err());
        assert!(ValidationContext::Resource.validate("User").is_err());
        assert!(ValidationContext::Resource.validate("_user").is_err());
        assert!(ValidationContext::Resource.validate("user_").is_err());
        assert!(ValidationContext::Resource.validate("self").is_err());
        assert!(ValidationContext::Resource.validate("user-name").is_err());
    }

    #[test]
    fn test_validate_field_name_valid() {
        assert!(ValidationContext::Field.validate("user").is_ok());
        assert!(ValidationContext::Field.validate("blog_post").is_ok());
        assert!(ValidationContext::Field.validate("item123").is_ok());
    }

    #[test]
    fn test_validate_field_name_invalid() {
        assert!(ValidationContext::Field.validate("").is_err());
        assert!(ValidationContext::Field.validate("User").is_err());
        assert!(ValidationContext::Field.validate("_user").is_err());
        assert!(ValidationContext::Field.validate("user_").is_err());
        assert!(ValidationContext::Field.validate("self").is_err());
        assert!(ValidationContext::Field.validate("user-name").is_err());
    }

    #[test]
    fn test_normalized_type_from_str() {
        use std::str::FromStr;

        // Primitives and common aliases
        assert_eq!(
            NormalizedType::from_str("string").unwrap(),
            NormalizedType::String
        );
        assert_eq!(
            NormalizedType::from_str("str").unwrap(),
            NormalizedType::String
        );
        assert_eq!(
            NormalizedType::from_str("text").unwrap(),
            NormalizedType::Text
        );
        assert_eq!(
            NormalizedType::from_str("i32").unwrap(),
            NormalizedType::I32
        );
        assert_eq!(
            NormalizedType::from_str("integer").unwrap(),
            NormalizedType::I32
        );
        assert_eq!(
            NormalizedType::from_str("int").unwrap(),
            NormalizedType::I32
        );
        assert_eq!(
            NormalizedType::from_str("i64").unwrap(),
            NormalizedType::I64
        );
        assert_eq!(
            NormalizedType::from_str("bigint").unwrap(),
            NormalizedType::I64
        );
        assert_eq!(
            NormalizedType::from_str("f32").unwrap(),
            NormalizedType::F32
        );
        assert_eq!(
            NormalizedType::from_str("float").unwrap(),
            NormalizedType::F32
        );
        assert_eq!(
            NormalizedType::from_str("f64").unwrap(),
            NormalizedType::F64
        );
        assert_eq!(
            NormalizedType::from_str("double").unwrap(),
            NormalizedType::F64
        );
        assert_eq!(
            NormalizedType::from_str("bool").unwrap(),
            NormalizedType::Bool
        );
        assert_eq!(
            NormalizedType::from_str("boolean").unwrap(),
            NormalizedType::Bool
        );
        assert_eq!(
            NormalizedType::from_str("uuid").unwrap(),
            NormalizedType::Uuid
        );

        // Date/Time
        assert_eq!(
            NormalizedType::from_str("datetimeutc").unwrap(),
            NormalizedType::DateTimeUtc
        );
        assert_eq!(
            NormalizedType::from_str("timestamptz").unwrap(),
            NormalizedType::DateTimeUtc
        );
        assert_eq!(
            NormalizedType::from_str("naivedatetime").unwrap(),
            NormalizedType::DateTime
        );
        assert_eq!(
            NormalizedType::from_str("timestamp").unwrap(),
            NormalizedType::DateTime
        );
        assert_eq!(
            NormalizedType::from_str("date").unwrap(),
            NormalizedType::Date
        );
        assert_eq!(
            NormalizedType::from_str("time").unwrap(),
            NormalizedType::Time
        );

        // Special types
        assert_eq!(
            NormalizedType::from_str("decimal").unwrap(),
            NormalizedType::Decimal
        );
        assert_eq!(
            NormalizedType::from_str("numeric").unwrap(),
            NormalizedType::Decimal
        );
        assert_eq!(
            NormalizedType::from_str("money").unwrap(),
            NormalizedType::Decimal
        );
        assert_eq!(
            NormalizedType::from_str("json").unwrap(),
            NormalizedType::Json
        );
        assert_eq!(
            NormalizedType::from_str("jsonb").unwrap(),
            NormalizedType::Json
        );
        assert_eq!(
            NormalizedType::from_str("bytes").unwrap(),
            NormalizedType::Bytes
        );
        assert_eq!(
            NormalizedType::from_str("blob").unwrap(),
            NormalizedType::Bytes
        );
        assert_eq!(
            NormalizedType::from_str("binary").unwrap(),
            NormalizedType::Bytes
        );
        assert_eq!(
            NormalizedType::from_str("bytea").unwrap(),
            NormalizedType::Bytes
        );
    }

    #[test]
    fn test_normalized_type_schema_name() {
        assert_eq!(NormalizedType::String.schema_type_name(), "String");
        assert_eq!(NormalizedType::Text.schema_type_name(), "Text");
        assert_eq!(NormalizedType::I32.schema_type_name(), "i32");
        assert_eq!(NormalizedType::I64.schema_type_name(), "i64");
        assert_eq!(NormalizedType::DateTimeUtc.schema_type_name(), "DateTime");
        assert_eq!(NormalizedType::DateTime.schema_type_name(), "NaiveDateTime");
        assert_eq!(NormalizedType::Bytes.schema_type_name(), "Vec<u8>");
        assert_eq!(NormalizedType::Time.schema_type_name(), "Time");
    }

    #[test]
    fn test_column_method_new() {
        assert_eq!(
            ColumnMethod::new(&NormalizedType::String, false).to_string(),
            ".string().not_null()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::String, true).to_string(),
            ".string()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::I32, false).to_string(),
            ".integer().not_null()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::Uuid, false).to_string(),
            ".uuid().not_null()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::Bytes, false).to_string(),
            ".binary().not_null()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::Time, false).to_string(),
            ".time().not_null()"
        );
        assert_eq!(
            ColumnMethod::new(&NormalizedType::DateTimeUtc, false).to_string(),
            ".timestamp_with_time_zone().not_null()"
        );
    }

    #[test]
    fn test_sea_orm_import_name() {
        assert_eq!(
            NormalizedType::DateTimeUtc.sea_orm_import_name(),
            Some("DateTimeUtc")
        );
        assert_eq!(
            NormalizedType::DateTime.sea_orm_import_name(),
            Some("DateTime")
        );
        assert_eq!(NormalizedType::Date.sea_orm_import_name(), Some("Date"));
        assert_eq!(NormalizedType::Json.sea_orm_import_name(), Some("Json"));
        assert_eq!(NormalizedType::Time.sea_orm_import_name(), Some("Time"));
        assert_eq!(NormalizedType::String.sea_orm_import_name(), None);
    }
}
