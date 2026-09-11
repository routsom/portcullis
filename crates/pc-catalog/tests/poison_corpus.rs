//! Corpus test for the poisoning scanner (CLAUDE.md §5 row #7). Every sample in
//! `testdata/poison/clean/` must score below the high-risk threshold, and every
//! sample in `testdata/poison/poison/` must score at or above it.

use std::path::Path;

use pc_catalog::scan;

fn corpus_dir(kind: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/poison/{kind}"))
}

fn samples(kind: &str) -> Vec<(String, String)> {
    let dir = corpus_dir(kind);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("corpus dir exists") {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "txt") {
            let text = std::fs::read_to_string(&path).unwrap();
            out.push((path.display().to_string(), text));
        }
    }
    assert!(!out.is_empty(), "corpus {kind} has samples");
    out
}

#[test]
fn clean_corpus_is_low_risk() {
    for (name, text) in samples("clean") {
        let report = scan(&text);
        assert!(
            !report.is_high_risk(),
            "clean sample {name} unexpectedly high-risk (score {})",
            report.score
        );
    }
}

#[test]
fn poison_corpus_is_high_risk() {
    for (name, text) in samples("poison") {
        let report = scan(&text);
        assert!(
            report.is_high_risk(),
            "poison sample {name} was not caught (score {})",
            report.score
        );
    }
}
