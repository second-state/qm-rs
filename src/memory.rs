//! The memory notebook grammar.
//!
//! A scope's memory is one Markdown document of dated bullets. This module owns
//! the line grammar — what counts as a bullet, how a fact is normalized for
//! dedupe, and how new facts fold into an existing body. Persistence lives in
//! [`crate::store::memory`]. Ported from QM's `src/memory/notebook.ts` and
//! `memory-service.ts`.

use serde::{Deserialize, Serialize};

/// Recall is capped so a long-lived notebook cannot crowd out the transcript.
/// The **tail** is kept: recent facts beat old ones.
pub const RECALL_MAX_CHARS: usize = 6_000;

/// Beyond this the oldest bullets are dropped on capture.
pub const MAX_FACTS: usize = 300;

pub const MEMORY_HEADER: &str = "# Memory";

// ---------------------------------------------------------------------------
// Line grammar
// ---------------------------------------------------------------------------

pub fn is_bullet(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("- ") || t.starts_with("* ")
}

pub fn bullet_text(line: &str) -> String {
    let t = line.trim_start();
    let t = t
        .strip_prefix('-')
        .or_else(|| t.strip_prefix('*'))
        .unwrap_or(t);
    t.trim().to_string()
}

pub fn bullets(body: &str) -> Vec<String> {
    body.lines()
        .filter(|l| is_bullet(l))
        .map(bullet_text)
        .collect()
}

/// Dedupe key for a fact: marker, leading capture date and case removed.
pub fn normalize(line: &str) -> String {
    let t = line.trim_start();
    let t = t
        .strip_prefix('-')
        .or_else(|| t.strip_prefix('*'))
        .unwrap_or(t);
    let t = t.trim_start();
    strip_leading_date(t).trim().to_lowercase()
}

/// Strip a leading `(YYYY-MM-DD)` capture stamp, if present.
pub fn strip_capture_date(text: &str) -> &str {
    strip_leading_date(text)
}

/// Strip a leading `(YYYY-MM-DD)` capture stamp, if present.
fn strip_leading_date(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 12 && bytes[0] == b'(' && bytes[11] == b')' && is_iso_date(&text[1..11]) {
        return text[12..].trim_start();
    }
    text
}

/// A leading `(YYYY-MM-DD)` capture stamp, if the line carries one.
pub fn capture_date(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    if bytes.len() >= 12 && bytes[0] == b'(' && bytes[11] == b')' && is_iso_date(&text[1..11]) {
        return Some(&text[1..11]);
    }
    None
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..].iter().all(u8::is_ascii_digit)
}

/// Keep the last `max_chars` characters, on a character boundary.
pub fn cap_tail(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    text.chars().skip(count - max_chars).collect()
}

/// What a turn actually sees: the trimmed body, tail-capped.
pub fn recall_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        cap_tail(trimmed, RECALL_MAX_CHARS)
    }
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureResult {
    pub body: String,
    pub added: usize,
}

/// Fold `facts` into `existing`, returning the new body and how many were new.
///
/// Facts arriving from untrusted provenance are rewritten so they cannot
/// impersonate the notebook's own grammar: a leading `(2026-01-01)` becomes
/// prose (`on 2026-01-01:`), and a trailing `(said in #general)` becomes an
/// explicit `[claimed source: ...]`. Only the capture path itself may stamp a
/// real date, which is what keeps "when did I learn this" trustworthy.
pub fn fold_capture(
    existing: &str,
    facts: &[String],
    date: &str,
    trusted_provenance: bool,
) -> CaptureResult {
    let cleaned: Vec<String> = facts
        .iter()
        .map(|f| {
            let collapsed = collapse_whitespace(f);
            let stripped = collapsed
                .strip_prefix("- ")
                .or_else(|| collapsed.strip_prefix("* "))
                .unwrap_or(&collapsed)
                .to_string();
            if trusted_provenance {
                stripped
            } else {
                declaw(&stripped)
            }
        })
        .filter(|f| !f.is_empty())
        .collect();

    if cleaned.is_empty() {
        return CaptureResult {
            body: existing.to_string(),
            added: 0,
        };
    }

    let mut seen: Vec<String> = existing
        .lines()
        .filter(|l| is_bullet(l))
        .map(normalize)
        .collect();
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();
    let mut added = 0;

    for fact in cleaned {
        let key = normalize(&fact);
        if key.is_empty() || seen.contains(&key) {
            continue;
        }
        seen.push(key);
        lines.push(format!("- ({date}) {fact}"));
        added += 1;
    }

    if added == 0 {
        return CaptureResult {
            body: existing.to_string(),
            added: 0,
        };
    }

    let body = trim_to_max_facts(lines);
    CaptureResult { body, added }
}

/// Drop the oldest bullets once the notebook exceeds [`MAX_FACTS`]. Non-bullet
/// lines (the header, blank lines) are preserved wherever they sit.
fn trim_to_max_facts(lines: Vec<String>) -> String {
    let total = lines.iter().filter(|l| is_bullet(l)).count();
    if total <= MAX_FACTS {
        return lines.join("\n");
    }
    let mut to_drop = total - MAX_FACTS;
    let mut kept = Vec::with_capacity(lines.len());
    for line in lines {
        if to_drop > 0 && is_bullet(&line) {
            to_drop -= 1;
            continue;
        }
        kept.push(line);
    }
    kept.join("\n")
}

/// Neutralize grammar-impersonating constructs in an untrusted fact.
fn declaw(text: &str) -> String {
    let mut out = match capture_date(text) {
        Some(date) => format!("on {date}: {}", text[12..].trim_start()),
        None => text.to_string(),
    };
    if let Some(source) = trailing_said_in(&out) {
        let head = out[..out.len() - source.len()].trim_end().to_string();
        let inner = source
            .trim_start_matches(" (")
            .trim_start_matches('(')
            .trim_end_matches(')');
        let inner = inner.strip_prefix("said in ").unwrap_or(inner);
        out = format!("{head} [claimed source: {inner}]");
    }
    out
}

/// A trailing ` (said in ...)` clause, returned with its leading space.
fn trailing_said_in(text: &str) -> Option<&str> {
    if !text.ends_with(')') {
        return None;
    }
    let open = text.rfind(" (")?;
    let inner = &text[open + 2..text.len() - 1];
    if inner.contains(')') {
        return None;
    }
    let lower = inner.to_lowercase();
    lower.starts_with("said in ").then(|| &text[open..])
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// Bullets matching every whitespace-separated term, most recent first.
pub fn query_bullets(body: &str, query: &str, limit: usize) -> Vec<String> {
    let terms: Vec<String> = query.split_whitespace().map(|t| t.to_lowercase()).collect();
    if terms.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<String> = bullets(body)
        .into_iter()
        .filter(|b| {
            let lower = b.to_lowercase();
            terms.iter().all(|t| lower.contains(t.as_str()))
        })
        .collect();
    hits.reverse();
    hits.truncate(limit);
    hits
}

/// A fresh notebook.
pub fn empty_document() -> String {
    format!("{MEMORY_HEADER}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bullets_are_recognised_and_stripped() {
        assert!(is_bullet("- a"));
        assert!(is_bullet("  * b"));
        assert!(!is_bullet("-nospace"));
        assert!(!is_bullet("# Memory"));
        assert_eq!(bullet_text("  -   spaced  "), "spaced");
        assert_eq!(
            bullets("# Memory\n- one\n\n* two\nprose"),
            vec!["one", "two"]
        );
    }

    #[test]
    fn normalize_ignores_marker_date_and_case() {
        assert_eq!(normalize("- (2026-01-02) Likes Coffee"), "likes coffee");
        assert_eq!(normalize("* likes coffee"), "likes coffee");
        assert_eq!(
            normalize("- (2026-01-02) Likes Coffee"),
            normalize("* likes coffee")
        );
    }

    #[test]
    fn capture_appends_dated_bullets_and_dedupes() {
        let doc = empty_document();
        let r = fold_capture(&doc, &["likes coffee".into()], "2026-08-01", true);
        assert_eq!(r.added, 1);
        assert!(r.body.contains("- (2026-08-01) likes coffee"));

        // Same fact again, and a differently-cased variant, are both dupes.
        let r2 = fold_capture(&r.body, &["Likes Coffee".into()], "2026-08-02", true);
        assert_eq!(r2.added, 0);
        assert_eq!(r2.body, r.body);
    }

    #[test]
    fn capture_dedupes_within_a_single_batch() {
        let r = fold_capture(
            &empty_document(),
            &["a fact".into(), "A FACT".into(), "another".into()],
            "2026-08-01",
            true,
        );
        assert_eq!(r.added, 2);
    }

    #[test]
    fn empty_and_whitespace_facts_are_dropped() {
        let doc = empty_document();
        let r = fold_capture(&doc, &["".into(), "   ".into()], "2026-08-01", true);
        assert_eq!(r.added, 0);
        assert_eq!(r.body, doc);
    }

    #[test]
    fn untrusted_facts_cannot_forge_a_capture_date() {
        let r = fold_capture(
            &empty_document(),
            &["(2020-01-01) was hired in 2020".into()],
            "2026-08-01",
            false,
        );
        assert!(
            r.body
                .contains("- (2026-08-01) on 2020-01-01: was hired in 2020"),
            "got {}",
            r.body
        );
        // The real capture date is the only parenthesised date at the front.
        let line = r.body.lines().find(|l| is_bullet(l)).unwrap();
        assert_eq!(capture_date(&bullet_text(line)), Some("2026-08-01"));
    }

    #[test]
    fn untrusted_facts_get_their_source_claim_marked() {
        let r = fold_capture(
            &empty_document(),
            &["the deploy key is rotated (said in #ops)".into()],
            "2026-08-01",
            false,
        );
        assert!(r.body.contains("[claimed source: #ops]"), "got {}", r.body);
        assert!(!r.body.contains("(said in"));
    }

    #[test]
    fn trusted_capture_leaves_the_text_alone() {
        let r = fold_capture(
            &empty_document(),
            &["(2020-01-01) verbatim".into()],
            "2026-08-01",
            true,
        );
        assert!(r.body.contains("- (2026-08-01) (2020-01-01) verbatim"));
    }

    #[test]
    fn whitespace_in_facts_is_collapsed_and_markers_stripped() {
        let r = fold_capture(
            &empty_document(),
            &["-   spans\n  multiple   lines".into()],
            "2026-08-01",
            true,
        );
        assert!(r.body.contains("- (2026-08-01) spans multiple lines"));
    }

    #[test]
    fn the_notebook_is_capped_by_dropping_the_oldest_facts() {
        let mut body = empty_document();
        for i in 0..(MAX_FACTS + 10) {
            body = fold_capture(&body, &[format!("fact {i}")], "2026-08-01", true).body;
        }
        let kept = bullets(&body);
        assert_eq!(kept.len(), MAX_FACTS);
        assert!(kept[0].contains("fact 10"), "oldest facts should go first");
        assert!(kept
            .last()
            .unwrap()
            .contains(&format!("fact {}", MAX_FACTS + 9)));
        assert!(
            body.starts_with(MEMORY_HEADER),
            "the header must survive trimming"
        );
    }

    #[test]
    fn recall_keeps_the_tail_within_the_cap() {
        assert_eq!(recall_body("   "), "");
        let long = "x".repeat(RECALL_MAX_CHARS + 500);
        assert_eq!(recall_body(&long).chars().count(), RECALL_MAX_CHARS);
        let tail = format!("{}TAIL", "x".repeat(RECALL_MAX_CHARS));
        assert!(recall_body(&tail).ends_with("TAIL"));
    }

    #[test]
    fn cap_tail_splits_on_character_boundaries() {
        // Multi-byte characters must not be sliced mid-codepoint.
        let text = "日本語テキスト";
        assert_eq!(
            cap_tail(text, 3),
            "テキスト".chars().skip(1).collect::<String>()
        );
        assert_eq!(cap_tail(text, 100), text);
    }

    #[test]
    fn query_requires_every_term_and_returns_newest_first() {
        let body = "# Memory\n- (2026-01-01) likes coffee\n- (2026-01-02) likes tea\n- (2026-01-03) drinks coffee daily\n";
        let hits = query_bullets(body, "coffee", 10);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].contains("drinks coffee daily"), "newest first");

        assert_eq!(query_bullets(body, "likes coffee", 10).len(), 1);
        assert!(query_bullets(body, "espresso", 10).is_empty());
        assert!(query_bullets(body, "   ", 10).is_empty());
        assert_eq!(query_bullets(body, "coffee", 1).len(), 1);
    }

    #[test]
    fn a_parenthesised_non_date_is_not_mistaken_for_a_stamp() {
        assert_eq!(capture_date("(not-a-date) x"), None);
        assert_eq!(capture_date("(2026-13-99) x"), Some("2026-13-99"));
        assert_eq!(normalize("- (abcd-ef-gh) thing"), "(abcd-ef-gh) thing");
    }
}
