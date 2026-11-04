mod parse;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const SQL_EXTENSIONS: &[&str] = &[
    "sql", "ddl", "dml", "psql", "mysql", "sqlite", "sqlite3", "db3",
];
const MAX_SCRIPT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Note,
    Warning,
    Danger,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Flag {
    pub level: Level,
    pub message: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Statement {
    pub line: usize,
    pub kind: String,
    pub summary: String,
    pub text: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub flags: Vec<Flag>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    Table,
    View,
    Trigger,
    Procedure,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Object {
    pub name: String,
    pub kind: ObjectKind,
    pub columns: Vec<String>,
    pub rows: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RelationKind {
    References,
    Feeds,
    Fires,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Relation {
    pub from: usize,
    pub to: usize,
    pub kind: RelationKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Script {
    pub source: String,
    pub statements: Vec<Statement>,
    pub objects: Vec<Object>,
    pub relations: Vec<Relation>,
}

impl Script {
    pub fn counts_by_kind(&self) -> BTreeMap<&str, usize> {
        let mut counts = BTreeMap::new();
        for statement in &self.statements {
            *counts.entry(statement.kind.as_str()).or_insert(0) += 1;
        }
        counts
    }

    pub fn flagged(&self) -> usize {
        self.statements
            .iter()
            .filter(|statement| !statement.flags.is_empty())
            .count()
    }
}

pub fn is_sql_file(path: &Path) -> bool {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase());
    if extension.is_some_and(|extension| SQL_EXTENSIONS.contains(&extension.as_str())) {
        return true;
    }
    has_sqlite_magic(path)
}

fn has_sqlite_magic(path: &Path) -> bool {
    use std::io::Read;

    let mut head = [0u8; SQLITE_MAGIC.len()];
    fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok()
        && head == SQLITE_MAGIC
}

// Reads the file only. SQL scripts are never executed, and SQLite files open read-only.
pub fn open(path: &Path) -> Result<Script> {
    let source = path.display().to_string();
    if has_sqlite_magic(path) {
        return open_sqlite(path, source);
    }

    let size = fs::metadata(path)
        .with_context(|| format!("cannot read {source}"))?
        .len();
    anyhow::ensure!(
        size <= MAX_SCRIPT_BYTES,
        "this SQL file is too large to inspect"
    );

    let bytes = fs::read(path).with_context(|| format!("cannot read {source}"))?;
    let mut script = parse::parse(&decode_text(&bytes));
    script.source = source;
    Ok(script)
}

fn open_sqlite(path: &Path, source: String) -> Result<Script> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open {source}"))?;

    let mut schema = String::new();
    let mut query = connection
        .prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL")
        .context("this SQLite file has no readable schema")?;
    let rows = query.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        schema.push_str(&row?);
        schema.push_str(";\n");
    }

    let mut script = parse::parse(&schema);
    script.source = source;
    for object in &mut script.objects {
        if object.kind == ObjectKind::Table {
            let count = format!(
                "SELECT count(*) FROM \"{}\"",
                object.name.replace('"', "\"\"")
            );
            object.rows = connection
                .query_row(&count, [], |row| row.get::<_, i64>(0))
                .ok()
                .and_then(|rows| u64::try_from(rows).ok());
        }
    }
    Ok(script)
}

fn decode_text(bytes: &[u8]) -> String {
    let wide = |pair: &[u8], little: bool| {
        if little {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        }
    };

    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| wide(pair, true))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| wide(pair, false))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("euphoria-sql-{}-{name}", std::process::id()))
    }

    #[test]
    fn opens_sqlite_read_only_and_reads_the_schema() {
        let path = scratch("sample.bin");
        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
                     CREATE TABLE orders (id INTEGER, user_id INTEGER REFERENCES users(id));
                     INSERT INTO users VALUES (1, 'a'), (2, 'b');",
                )
                .unwrap();
        }
        let before = fs::read(&path).unwrap();

        assert!(is_sql_file(&path));
        let script = open(&path).unwrap();
        let after = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(before, after);
        let users = script.objects.iter().find(|o| o.name == "users").unwrap();
        assert_eq!(users.rows, Some(2));
        assert_eq!(users.columns, ["id", "name"]);
        assert_eq!(script.relations.len(), 1);
    }

    #[test]
    fn decodes_utf16_scripts() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend("DROP TABLE a;".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_text(&bytes), "DROP TABLE a;");
    }

    #[test]
    fn recognizes_sql_files_by_extension() {
        assert!(is_sql_file(Path::new("dump.SQL")));
        assert!(!is_sql_file(Path::new("program.exe")));
    }
}
