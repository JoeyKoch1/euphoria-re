use std::collections::{BTreeMap, BTreeSet};

use crate::{Flag, Level, Object, ObjectKind, Relation, RelationKind, Script, Statement};

const MAX_TEXT_CHARS: usize = 400;
const DEFAULT_SCHEMAS: &[&str] = &["dbo", "public", "main"];
const NOT_COLUMNS: &[&str] = &[
    "PRIMARY",
    "FOREIGN",
    "CONSTRAINT",
    "UNIQUE",
    "KEY",
    "INDEX",
    "CHECK",
    "FULLTEXT",
    "SPATIAL",
    "EXCLUDE",
    "LIKE",
    "PERIOD",
];
const NOT_NAMES: &[&str] = &[
    "SELECT",
    "WHERE",
    "SET",
    "VALUES",
    "ON",
    "AS",
    "IF",
    "TABLE",
    "ONLY",
    "LATERAL",
    "GROUP",
    "ORDER",
    "HAVING",
    "LIMIT",
    "UNION",
    "JOIN",
    "INNER",
    "LEFT",
    "RIGHT",
    "FULL",
    "CROSS",
    "OUTER",
    "NATURAL",
    "USING",
    "FROM",
    "INTO",
    "RETURNING",
];
const WORD_FLAGS: &[(&str, Level, &str)] = &[
    (
        "XP_CMDSHELL",
        Level::Danger,
        "Runs operating system commands",
    ),
    (
        "SP_OACREATE",
        Level::Danger,
        "Creates COM objects on the server",
    ),
    (
        "SP_CONFIGURE",
        Level::Warning,
        "Changes server configuration",
    ),
    (
        "OPENROWSET",
        Level::Warning,
        "Reads data from an external source",
    ),
    ("LOAD_FILE", Level::Danger, "Reads a file from the server"),
    (
        "OUTFILE",
        Level::Danger,
        "Writes query results to a server file",
    ),
    (
        "DUMPFILE",
        Level::Danger,
        "Writes query results to a server file",
    ),
    ("PROGRAM", Level::Warning, "May run a program on the server"),
    ("ATTACH", Level::Warning, "Attaches another database file"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Text,
    Symbol(char),
}

#[derive(Clone, Debug)]
struct Spanned {
    token: Token,
    line: usize,
    start: usize,
    end: usize,
}

fn tokenize(source: &str) -> Vec<Spanned> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut at = 0;

    let is_word = |byte: u8| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@' | b'#' | b'$') || byte >= 0x80
    };

    while at < bytes.len() {
        let start = at;
        let start_line = line;
        let byte = bytes[at];

        let token = match byte {
            b'\n' => {
                line += 1;
                at += 1;
                None
            }
            _ if byte.is_ascii_whitespace() => {
                at += 1;
                None
            }
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
                None
            }
            b'#' if bytes.get(at + 1).is_none_or(u8::is_ascii_whitespace) => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
                None
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                at += 2;
                while at < bytes.len() && !(bytes[at] == b'*' && bytes.get(at + 1) == Some(&b'/')) {
                    line += usize::from(bytes[at] == b'\n');
                    at += 1;
                }
                at = (at + 2).min(bytes.len());
                None
            }
            b'\'' | b'"' | b'`' | b'[' => {
                let close = if byte == b'[' { b']' } else { byte };
                at += 1;
                let body = at;
                while at < bytes.len() {
                    if bytes[at] == b'\\' && byte == b'\'' {
                        at = (at + 2).min(bytes.len());
                        continue;
                    }
                    if bytes[at] == close {
                        if bytes.get(at + 1) == Some(&close) && byte != b'[' {
                            at += 2;
                            continue;
                        }
                        break;
                    }
                    line += usize::from(bytes[at] == b'\n');
                    at += 1;
                }
                let end = at.min(bytes.len());
                at = (at + 1).min(bytes.len());
                Some(if byte == b'\'' {
                    Token::Text
                } else {
                    Token::Quoted(source[body..end].to_owned())
                })
            }
            b'$' if dollar_tag_end(bytes, at).is_some() => {
                let tag_end = dollar_tag_end(bytes, at).unwrap_or(at);
                let tag = &source[at..tag_end];
                let close = source[tag_end..].find(tag).map(|found| tag_end + found);
                let end = close.map_or(bytes.len(), |close| close + tag.len());
                line += source[at..end].matches('\n').count();
                at = end;
                Some(Token::Text)
            }
            _ if is_word(byte) => {
                while at < bytes.len() && is_word(bytes[at]) {
                    at += 1;
                }
                Some(Token::Word(source[start..at].to_owned()))
            }
            _ => {
                at += 1;
                Some(Token::Symbol(char::from(byte)))
            }
        };

        if let Some(token) = token {
            tokens.push(Spanned {
                token,
                line: start_line,
                start,
                end: at,
            });
        }
    }
    tokens
}

fn dollar_tag_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut end = at + 1;
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    (bytes.get(end) == Some(&b'$')).then_some(end + 1)
}

fn upper(token: &Spanned) -> Option<String> {
    match &token.token {
        Token::Word(word) => Some(word.to_ascii_uppercase()),
        _ => None,
    }
}

fn split_statements(tokens: &[Spanned], source: &str) -> Vec<Vec<Spanned>> {
    let mut statements = Vec::new();
    let mut current: Vec<Spanned> = Vec::new();
    let mut block_depth = 0usize;
    let mut has_body = false;

    for (index, token) in tokens.iter().enumerate() {
        let word = upper(token);
        if current.is_empty() {
            block_depth = 0;
            has_body = false;
        }

        match word.as_deref() {
            Some("GO") if is_alone_on_line(token, source) => {
                if !current.is_empty() {
                    statements.push(std::mem::take(&mut current));
                }
                continue;
            }
            Some("TRIGGER" | "PROCEDURE" | "PROC" | "FUNCTION")
                if current.first().and_then(upper).as_deref() == Some("CREATE") =>
            {
                has_body = true;
            }
            Some("BEGIN" | "CASE") if has_body => block_depth += 1,
            Some("END") if has_body => {
                let next = tokens.get(index + 1).and_then(upper);
                if !matches!(
                    next.as_deref(),
                    Some("IF" | "LOOP" | "WHILE" | "REPEAT" | "FOR")
                ) {
                    block_depth = block_depth.saturating_sub(1);
                }
            }
            _ => {}
        }

        if token.token == Token::Symbol(';') && block_depth == 0 {
            if !current.is_empty() {
                statements.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(token.clone());
    }

    if !current.is_empty() {
        statements.push(current);
    }
    statements
}

fn is_alone_on_line(token: &Spanned, source: &str) -> bool {
    let before = source[..token.start].rsplit('\n').next().unwrap_or("");
    let after = source[token.end..].split('\n').next().unwrap_or("");
    before.trim().is_empty() && after.trim().is_empty()
}

fn normalize(parts: &[String]) -> String {
    let mut parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    while parts.len() > 1 && DEFAULT_SCHEMAS.contains(&parts[0].to_ascii_lowercase().as_str()) {
        parts.remove(0);
    }
    parts.join(".").to_lowercase()
}

struct Reader<'a> {
    tokens: &'a [Spanned],
}

impl Reader<'_> {
    fn word(&self, at: usize) -> Option<String> {
        self.tokens.get(at).and_then(upper)
    }

    fn is_symbol(&self, at: usize, symbol: char) -> bool {
        self.tokens
            .get(at)
            .is_some_and(|t| t.token == Token::Symbol(symbol))
    }

    // Reads a possibly dotted name and returns it with the index after it.
    fn name(&self, mut at: usize) -> Option<(String, usize)> {
        while matches!(
            self.word(at).as_deref(),
            Some(
                "IF" | "NOT"
                    | "EXISTS"
                    | "ONLY"
                    | "TEMP"
                    | "TEMPORARY"
                    | "TABLE"
                    | "OR"
                    | "REPLACE"
            )
        ) {
            at += 1;
        }

        let mut parts = Vec::new();
        loop {
            match &self.tokens.get(at)?.token {
                Token::Word(word) => {
                    if parts.is_empty() && NOT_NAMES.contains(&word.to_ascii_uppercase().as_str()) {
                        return None;
                    }
                    parts.push(word.clone());
                }
                Token::Quoted(word) => parts.push(word.clone()),
                _ => return None,
            }
            at += 1;
            if self.is_symbol(at, '.') {
                at += 1;
            } else {
                break;
            }
        }

        if self.is_symbol(at, '(') && parts.len() == 1 && !self.starts_definition(at) {
            return None;
        }
        Some((normalize(&parts), at))
    }

    fn starts_definition(&self, at: usize) -> bool {
        (0..at).any(|index| {
            matches!(
                self.word(index).as_deref(),
                Some("CREATE" | "INSERT" | "REFERENCES" | "REPLACE" | "VIEW" | "COPY")
            )
        })
    }

    fn has_word(&self, target: &str) -> bool {
        self.tokens
            .iter()
            .any(|token| upper(token).as_deref() == Some(target))
    }

    // Reads `FROM a x, b AS y` style lists, stopping at the first thing that is not a table.
    fn table_list(&self, mut at: usize, into: &mut Vec<String>) {
        loop {
            let Some((name, next)) = self.name(at) else {
                return;
            };
            into.push(name);
            at = next;
            if self.word(at).as_deref() == Some("AS") {
                at += 1;
            }
            if let Some(word) = self.word(at)
                && !NOT_NAMES.contains(&word.as_str())
            {
                at += 1;
            } else if matches!(
                self.tokens.get(at).map(|t| &t.token),
                Some(Token::Quoted(_))
            ) {
                at += 1;
            }
            if self.is_symbol(at, ',') {
                at += 1;
            } else {
                return;
            }
        }
    }

    fn cte_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        if self.word(0).as_deref() != Some("WITH") {
            return names;
        }
        for at in 1..self.tokens.len() {
            if self.word(at).as_deref() == Some("AS")
                && (self.is_symbol(at + 1, '(')
                    || self.word(at + 1).as_deref() == Some("MATERIALIZED"))
                && let Some(Token::Word(name) | Token::Quoted(name)) =
                    self.tokens.get(at - 1).map(|t| &t.token)
            {
                names.insert(name.to_lowercase());
            }
        }
        names
    }

    fn columns(&self, open: usize) -> Vec<String> {
        let mut columns = Vec::new();
        let mut depth = 0usize;
        let mut expect = true;
        for at in open..self.tokens.len() {
            match &self.tokens[at].token {
                Token::Symbol('(') => {
                    depth += 1;
                    continue;
                }
                Token::Symbol(')') => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                Token::Symbol(',') if depth == 1 => {
                    expect = true;
                    continue;
                }
                _ => {}
            }
            if depth == 1 && expect {
                expect = false;
                match &self.tokens[at].token {
                    Token::Word(word)
                        if !NOT_COLUMNS.contains(&word.to_ascii_uppercase().as_str()) =>
                    {
                        columns.push(word.clone());
                    }
                    Token::Quoted(word) => columns.push(word.clone()),
                    _ => {}
                }
            }
        }
        columns
    }
}

fn kind_of(reader: &Reader<'_>) -> String {
    let first = reader.word(0).unwrap_or_else(|| "OTHER".to_owned());
    match first.as_str() {
        "CREATE" | "ALTER" | "DROP" => {
            let object = (1..6)
                .filter_map(|at| reader.word(at))
                .find(|word| {
                    !matches!(
                        word.as_str(),
                        "OR" | "REPLACE"
                            | "TEMP"
                            | "TEMPORARY"
                            | "UNIQUE"
                            | "GLOBAL"
                            | "LOCAL"
                            | "IF"
                            | "NOT"
                            | "EXISTS"
                            | "VIRTUAL"
                            | "MATERIALIZED"
                            | "DEFINER"
                            | "RECURSIVE"
                            | "CLUSTERED"
                            | "NONCLUSTERED"
                    )
                })
                .unwrap_or_default();
            format!("{first} {object}").trim().to_owned()
        }
        "WITH" => {
            let main = ["INSERT", "UPDATE", "DELETE", "MERGE", "SELECT"]
                .into_iter()
                .find(|word| reader.has_word(word));
            main.unwrap_or("SELECT").to_owned()
        }
        "EXECUTE" | "CALL" => "EXEC".to_owned(),
        _ => first,
    }
}

fn collect(reader: &Reader<'_>, kind: &str) -> (Vec<String>, Vec<String>) {
    let mut reads = Vec::new();
    let mut writes = Vec::new();

    for at in 0..reader.tokens.len() {
        let Some(word) = reader.word(at) else {
            continue;
        };
        let previous = at.checked_sub(1).and_then(|before| reader.word(before));
        match word.as_str() {
            "FROM" => {
                if matches!(kind, "DELETE") && writes.is_empty() {
                    if let Some((name, _)) = reader.name(at + 1) {
                        writes.push(name);
                    }
                } else if kind == "COPY" {
                    continue;
                } else {
                    reader.table_list(at + 1, &mut reads);
                }
            }
            "JOIN" => {
                if let Some((name, _)) = reader.name(at + 1) {
                    reads.push(name);
                }
            }
            "INTO" => {
                if !matches!(reader.word(at + 1).as_deref(), Some("OUTFILE" | "DUMPFILE"))
                    && let Some((name, _)) = reader.name(at + 1)
                {
                    writes.push(name);
                }
            }
            "UPDATE"
                if !matches!(
                    previous.as_deref(),
                    Some("ON" | "FOR" | "AFTER" | "BEFORE" | "OF" | "KEY" | "OR" | "INSTEAD")
                ) =>
            {
                if let Some((name, _)) = reader.name(at + 1) {
                    writes.push(name);
                }
            }
            "DELETE" if at == 0 && reader.word(1).as_deref() != Some("FROM") => {
                if let Some((name, _)) = reader.name(1) {
                    writes.push(name);
                }
            }
            "TRUNCATE" | "MERGE" | "COPY" if at == 0 => {
                if let Some((name, _)) = reader.name(1) {
                    writes.push(name);
                }
            }
            _ => {}
        }
    }

    let cte = reader.cte_names();
    let keep = |name: &String| !cte.contains(name);
    reads.retain(keep);
    writes.retain(keep);
    reads.sort();
    reads.dedup();
    writes.sort();
    writes.dedup();
    (reads, writes)
}

fn flags_for(reader: &Reader<'_>, kind: &str) -> Vec<Flag> {
    let mut flags = Vec::new();
    let mut flag = |level, message| {
        let item = Flag { level, message };
        if !flags.contains(&item) {
            flags.push(item);
        }
    };

    if kind.starts_with("DROP") {
        flag(Level::Danger, "Deletes an object and everything in it");
    }
    if kind == "TRUNCATE" {
        flag(Level::Danger, "Empties a whole table");
    }
    if kind == "DELETE" && !reader.has_word("WHERE") {
        flag(Level::Danger, "Deletes every row, with no WHERE clause");
    }
    if kind == "UPDATE" && !reader.has_word("WHERE") {
        flag(Level::Warning, "Changes every row, with no WHERE clause");
    }
    if matches!(kind, "GRANT" | "REVOKE") {
        flag(Level::Warning, "Changes who can do what");
    }
    if matches!(
        kind,
        "CREATE USER" | "ALTER USER" | "CREATE LOGIN" | "ALTER LOGIN" | "CREATE ROLE"
    ) {
        flag(Level::Warning, "Changes accounts or passwords");
    }
    if kind == "EXEC" {
        flag(Level::Note, "Runs a stored procedure or dynamic SQL");
    }
    if kind == "LOAD" {
        flag(Level::Warning, "Loads data or code from a file");
    }

    for token in reader.tokens {
        if let Some(word) = upper(token)
            && let Some((_, level, message)) = WORD_FLAGS.iter().find(|(name, _, _)| *name == word)
        {
            flag(*level, *message);
        }
    }
    flags
}

fn summarize(
    kind: &str,
    name: Option<&str>,
    reads: &[String],
    writes: &[String],
    columns: usize,
) -> String {
    let list = |names: &[String]| names.join(", ");
    let target = name.map(str::to_owned).unwrap_or_else(|| list(writes));
    match kind {
        "CREATE TABLE" if columns > 0 => format!("Creates table {target} with {columns} columns"),
        "CREATE TABLE" => format!("Creates table {target}"),
        "CREATE VIEW" => format!("Creates view {target} over {}", list(reads)),
        "CREATE INDEX" => format!("Creates index {target}"),
        "CREATE TRIGGER" => format!("Creates trigger {target}"),
        "CREATE PROCEDURE" | "CREATE PROC" | "CREATE FUNCTION" => {
            format!("Creates routine {target}")
        }
        "ALTER TABLE" => format!("Changes table {target}"),
        "DROP TABLE" => format!("Deletes table {target}"),
        "TRUNCATE" => format!("Empties {target}"),
        "INSERT" | "REPLACE" if !reads.is_empty() => {
            format!("Copies rows from {} into {target}", list(reads))
        }
        "INSERT" | "REPLACE" => format!("Adds rows to {target}"),
        "UPDATE" => format!("Changes rows in {target}"),
        "DELETE" => format!("Deletes rows from {target}"),
        "MERGE" => format!("Merges rows into {target}"),
        "SELECT" if !reads.is_empty() => format!("Reads {}", list(reads)),
        "SELECT" => "Runs a query".to_owned(),
        "EXEC" => "Runs a routine".to_owned(),
        "BEGIN" | "START" => "Starts a transaction".to_owned(),
        "COMMIT" => "Saves the transaction".to_owned(),
        "ROLLBACK" => "Cancels the transaction".to_owned(),
        "USE" => "Switches database".to_owned(),
        "SET" | "PRAGMA" => "Changes a session setting".to_owned(),
        _ => kind.to_lowercase(),
    }
}

#[derive(Default)]
struct Graph {
    objects: Vec<Object>,
    index: BTreeMap<String, usize>,
    relations: BTreeSet<Relation>,
}

impl Graph {
    fn object(&mut self, name: &str) -> usize {
        if let Some(&index) = self.index.get(name) {
            return index;
        }
        self.objects.push(Object {
            name: name.to_owned(),
            kind: ObjectKind::Unknown,
            columns: Vec::new(),
            rows: None,
        });
        self.index.insert(name.to_owned(), self.objects.len() - 1);
        self.objects.len() - 1
    }

    fn define(&mut self, name: &str, kind: ObjectKind, columns: Vec<String>) {
        let index = self.object(name);
        self.objects[index].kind = kind;
        if !columns.is_empty() {
            self.objects[index].columns = columns;
        }
    }

    fn relate(&mut self, from: &str, to: &str, kind: RelationKind) {
        let relation = Relation {
            from: self.object(from),
            to: self.object(to),
            kind,
        };
        if relation.from != relation.to {
            self.relations.insert(relation);
        }
    }
}

fn analyze(tokens: &[Spanned], source: &str, graph: &mut Graph) -> Statement {
    let reader = Reader { tokens };
    let kind = kind_of(&reader);
    let (mut reads, mut writes) = collect(&reader, &kind);

    let mut defined = None;
    let mut columns = Vec::new();
    let object_keyword = kind.split(' ').nth(1).unwrap_or("");
    if matches!(kind.split(' ').next(), Some("CREATE" | "ALTER" | "DROP")) {
        let keyword = (1..8).find(|&at| reader.word(at).as_deref() == Some(object_keyword));
        if let Some((name, next)) = keyword.and_then(|at| reader.name(at + 1)) {
            defined = Some(name);
            if kind == "CREATE TABLE" && reader.is_symbol(next, '(') {
                columns = reader.columns(next);
            }
        }
    }

    if let Some(name) = &defined {
        let object_kind = match object_keyword {
            "TABLE" => Some(ObjectKind::Table),
            "VIEW" => Some(ObjectKind::View),
            "TRIGGER" => Some(ObjectKind::Trigger),
            "PROCEDURE" | "PROC" | "FUNCTION" => Some(ObjectKind::Procedure),
            _ => None,
        };
        if kind.starts_with("CREATE") {
            if let Some(object_kind) = object_kind {
                graph.define(name, object_kind, columns.clone());
            }
            if object_keyword == "INDEX" {
                if let Some(on) =
                    (2..tokens.len()).find(|&at| reader.word(at).as_deref() == Some("ON"))
                    && let Some((table, _)) = reader.name(on + 1)
                {
                    writes.push(table);
                }
            } else {
                writes.push(name.clone());
            }
        } else if matches!(object_keyword, "TABLE" | "VIEW") {
            writes.push(name.clone());
        }
    }

    if object_keyword == "TRIGGER" && kind.starts_with("CREATE") {
        if let Some(name) = &defined
            && let Some(on) = (2..tokens.len()).find(|&at| reader.word(at).as_deref() == Some("ON"))
            && let Some((table, _)) = reader.name(on + 1)
        {
            graph.relate(&table, name, RelationKind::Fires);
            reads.retain(|read| read != &table);
            for write in writes.iter().filter(|write| *write != name) {
                graph.relate(name, write, RelationKind::Feeds);
            }
        }
    } else {
        for read in &reads {
            for write in &writes {
                graph.relate(read, write, RelationKind::Feeds);
            }
        }
    }

    let owner = defined.clone().or_else(|| writes.first().cloned());
    for at in 0..tokens.len() {
        if reader.word(at).as_deref() == Some("REFERENCES")
            && let Some((parent, _)) = reader.name(at + 1)
            && let Some(owner) = &owner
        {
            graph.relate(owner, &parent, RelationKind::References);
        }
    }

    for name in reads.iter().chain(&writes) {
        graph.object(name);
    }
    writes.sort();
    writes.dedup();

    let summary = summarize(&kind, defined.as_deref(), &reads, &writes, columns.len());
    let flags = flags_for(&reader, &kind);
    let start = tokens.first().map_or(0, |token| token.start);
    let end = tokens.last().map_or(start, |token| token.end);
    let text: String = source[start..end].chars().take(MAX_TEXT_CHARS).collect();

    Statement {
        line: tokens.first().map_or(1, |token| token.line),
        kind,
        summary,
        text,
        reads,
        writes,
        flags,
    }
}

pub fn parse(source: &str) -> Script {
    let tokens = tokenize(source);
    let mut graph = Graph::default();
    let statements = split_statements(&tokens, source)
        .iter()
        .map(|statement| analyze(statement, source, &mut graph))
        .collect();

    Script {
        source: String::new(),
        statements,
        objects: graph.objects,
        relations: graph.relations.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object<'a>(script: &'a Script, name: &str) -> &'a Object {
        script.objects.iter().find(|o| o.name == name).unwrap()
    }

    fn related(script: &Script, from: &str, to: &str, kind: RelationKind) -> bool {
        script.relations.iter().any(|relation| {
            script.objects[relation.from].name == from
                && script.objects[relation.to].name == to
                && relation.kind == kind
        })
    }

    #[test]
    fn splits_statements_around_strings_and_comments() {
        let script = parse(
            "-- first; not a split\nINSERT INTO a VALUES ('x;y'); /* ; */ SELECT 1;\n\nSELECT * FROM b",
        );
        assert_eq!(script.statements.len(), 3);
        assert_eq!(script.statements[0].kind, "INSERT");
        assert_eq!(script.statements[2].line, 4);
    }

    #[test]
    fn reads_table_definitions_and_foreign_keys() {
        let script = parse(
            "CREATE TABLE IF NOT EXISTS public.users (id INT PRIMARY KEY, name VARCHAR(20), CONSTRAINT u UNIQUE (name));
             CREATE TABLE `orders` (id INT, user_id INT, FOREIGN KEY (user_id) REFERENCES users(id));",
        );

        assert_eq!(script.statements[0].kind, "CREATE TABLE");
        assert_eq!(
            script.statements[0].summary,
            "Creates table users with 2 columns"
        );
        assert_eq!(object(&script, "users").columns, ["id", "name"]);
        assert_eq!(object(&script, "orders").kind, ObjectKind::Table);
        assert!(related(
            &script,
            "orders",
            "users",
            RelationKind::References
        ));
    }

    #[test]
    fn traces_data_flow_through_queries_and_views() {
        let script = parse(
            "INSERT INTO archive SELECT * FROM orders o JOIN users u ON o.id = u.id;
             CREATE VIEW recent AS SELECT id FROM orders WHERE id > 5;
             WITH t AS (SELECT * FROM logs) UPDATE stats SET n = 1;",
        );

        assert_eq!(script.statements[0].reads, ["orders", "users"]);
        assert_eq!(script.statements[0].writes, ["archive"]);
        assert!(related(&script, "orders", "archive", RelationKind::Feeds));
        assert!(related(&script, "orders", "recent", RelationKind::Feeds));
        assert_eq!(object(&script, "recent").kind, ObjectKind::View);
        assert_eq!(script.statements[2].kind, "UPDATE");
        assert!(!script.statements[2].reads.contains(&"t".to_owned()));
        assert!(script.statements[2].reads.contains(&"logs".to_owned()));
    }

    #[test]
    fn keeps_trigger_bodies_in_one_statement() {
        let script = parse(
            "CREATE TRIGGER audit AFTER UPDATE ON users FOR EACH ROW BEGIN
                 INSERT INTO log VALUES (1);
                 UPDATE stats SET n = n + 1;
             END;
             SELECT 1;",
        );

        assert_eq!(script.statements.len(), 2);
        assert_eq!(script.statements[0].kind, "CREATE TRIGGER");
        assert!(related(&script, "users", "audit", RelationKind::Fires));
        assert!(related(&script, "audit", "log", RelationKind::Feeds));
        assert_eq!(object(&script, "audit").kind, ObjectKind::Trigger);
    }

    #[test]
    fn handles_batch_separators_and_dollar_quotes() {
        let script = parse(
            "SELECT * FROM [dbo].[Users]\nGO\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1; SELECT 2; $$ LANGUAGE sql;",
        );
        assert_eq!(script.statements.len(), 2);
        assert_eq!(script.statements[0].reads, ["users"]);
        assert_eq!(script.statements[1].kind, "CREATE FUNCTION");
    }

    #[test]
    fn flags_dangerous_statements() {
        let script = parse(
            "DROP TABLE users;
             DELETE FROM logs;
             DELETE FROM logs WHERE id = 1;
             UPDATE users SET admin = 1;
             EXEC xp_cmdshell 'whoami';
             SELECT * INTO OUTFILE '/tmp/x' FROM users;
             GRANT ALL ON a TO b;",
        );

        let levels: Vec<Option<Level>> = script
            .statements
            .iter()
            .map(|statement| statement.flags.first().map(|flag| flag.level))
            .collect();
        assert_eq!(
            levels,
            [
                Some(Level::Danger),
                Some(Level::Danger),
                None,
                Some(Level::Warning),
                Some(Level::Note),
                Some(Level::Danger),
                Some(Level::Warning),
            ]
        );
        assert!(
            script.statements[4]
                .flags
                .iter()
                .any(|flag| flag.level == Level::Danger)
        );
        assert_eq!(script.statements[5].reads, ["users"]);
        assert_eq!(script.flagged(), 6);
    }

    #[test]
    fn does_not_treat_functions_or_subqueries_as_tables() {
        let script =
            parse("SELECT * FROM (SELECT 1) x, generate_series(1, 3); SELECT now() FROM dual;");
        assert!(script.statements[0].reads.is_empty());
        assert_eq!(script.statements[1].reads, ["dual"]);
    }

    #[test]
    fn survives_garbage() {
        for source in [
            "",
            ";;;",
            "'unterminated",
            "/* open",
            "$$ open",
            "(((",
            "CREATE",
            "DROP TABLE",
            "\u{1F600}",
        ] {
            let _ = parse(source);
        }
    }
}
