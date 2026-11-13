//! The vector file as it is written: JSON with its objects in the order
//! the file has them, for the generators that add to it.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value as Json;

/// JSON with its objects in the order the file has them, so that adding
/// to the file leaves the rest of it byte for byte as it was.
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl<'de> Deserialize<'de> for J {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<J, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = J;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unsigned numbers")
            }
            fn visit_unit<E: de::Error>(self) -> Result<J, E> {
                Ok(J::Null)
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> Result<J, E> {
                Ok(J::Bool(b))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> Result<J, E> {
                Ok(J::Num(n))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<J, E> {
                Ok(J::Str(s.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut items = Vec::new();
                while let Some(x) = a.next_element()? {
                    items.push(x);
                }
                Ok(J::Arr(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut entries = Vec::new();
                while let Some(e) = a.next_entry()? {
                    entries.push(e);
                }
                Ok(J::Obj(entries))
            }
        }
        d.deserialize_any(V)
    }
}

/// New entries come from `serde_json`, whose objects are sorted.
pub fn from_json(j: &Json) -> J {
    match j {
        Json::Null => J::Null,
        Json::Bool(b) => J::Bool(*b),
        Json::Number(n) => J::Num(n.as_u64().expect("unsigned")),
        Json::String(s) => J::Str(s.clone()),
        Json::Array(a) => J::Arr(a.iter().map(from_json).collect()),
        Json::Object(m) => J::Obj(m.iter().map(|(k, v)| (k.clone(), from_json(v))).collect()),
    }
}

pub fn obj_mut(j: &mut J) -> &mut Vec<(String, J)> {
    match j {
        J::Obj(entries) => entries,
        other => panic!("not an object: {other:?}"),
    }
}

/// Replace `key` where it is, or add it: in key order if `sorted`, else
/// last.
pub fn upsert(entries: &mut Vec<(String, J)>, key: &str, value: J, sorted: bool) {
    if let Some(e) = entries.iter_mut().find(|(k, _)| k == key) {
        e.1 = value;
        return;
    }
    let at = if sorted {
        entries
            .iter()
            .position(|(k, _)| k.as_str() > key)
            .unwrap_or(entries.len())
    } else {
        entries.len()
    };
    entries.insert(at, (key.into(), value));
}

/// The file's layout: one space of indent per level, and every character
/// outside printable ASCII escaped.
pub fn render(j: &J) -> String {
    let mut out = String::new();
    write(j, 0, &mut out);
    out.push('\n');
    out
}

fn write(j: &J, depth: usize, out: &mut String) {
    let newline = |depth: usize, out: &mut String| {
        out.push('\n');
        out.push_str(&" ".repeat(depth));
    };
    match j {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Str(s) => escape(s, out),
        J::Arr(items) if items.is_empty() => out.push_str("[]"),
        J::Obj(entries) if entries.is_empty() => out.push_str("{}"),
        J::Arr(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(depth + 1, out);
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.push(']');
        }
        J::Obj(entries) => {
            out.push('{');
            for (i, (k, x)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(depth + 1, out);
                escape(k, out);
                out.push_str(": ");
                write(x, depth + 1, out);
            }
            newline(depth, out);
            out.push('}');
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out.push('"');
}
