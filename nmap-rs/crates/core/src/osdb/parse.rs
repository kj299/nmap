//! The `nmap-os-db` parser — a port of `parse_fingerprint_file()` and friends from
//! `osscan.cc`.
//!
//! The file is line-oriented:
//!
//! ```text
//! MatchPoints
//! SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100)
//! ...
//!
//! Fingerprint Linux 5.4
//! Class Linux | Linux | 5.X | general purpose
//! CPE cpe:/o:linux:linux_kernel:5 auto
//! SEQ(SP=100-10A%GCD=1-6%ISR=105-10F%TI=Z%CI=Z%II=I%TS=A)
//! T1(R=Y%DF=Y%T=3B-45%S=O%A=S+%F=AS%RD=0%Q=)
//! ```
//!
//! ## Untrusted input
//!
//! `--osscandb <file>` points this parser at an arbitrary file, so it is a Phase-0
//! threat-model boundary exactly like `nmap-service-probes` was in M3. The C reacts to
//! malformed input with a mix of `error()` (warn and continue) and **`fatal()`** (abort
//! the whole scan); this port localizes every failure into a [`DbWarning`] and keeps
//! going, so a corrupt or hostile database costs fingerprints rather than the run.
//!
//! ## Divergences (ledgered in `DIVERGENCES.md`)
//!
//! * `osdb-parse-degrade` — no input aborts the parse. The C `fatal()`s on: a second
//!   `MatchPoints` block, an unparseable `MatchPoints` attribute, a `Fingerprint` line
//!   with no terminator or an empty OS name, a `Class` line with too few `|` fields, and
//!   a `CPE` line with no preceding `Class`. Each becomes a warning here.
//! * `osdb-parse-skips-only-the-bad-line` — on a malformed test line the C does
//!   `goto top`, abandoning the *rest of the current record* (its remaining lines are
//!   then reported as stray top-level parse errors). This port drops just the offending
//!   line and keeps the record's other tests. Unreachable on the shipped file, which
//!   parses with zero warnings.

use super::model::{
    DbWarning, FingerPrint, FingerPrintDb, FingerTest, MatchPoints, OsClass, TestId,
};

/// Parse a `TEST(attr=value%attr=value…)` line into its attribute slots.
///
/// `apply_r_defaults` selects which of the C's two parsers this is:
///   * `true`  — `FingerTest::str2AVal`, used for a fingerprint record's test lines,
///     which defaults the `R` attribute to `Y`/`N` and rejects a contradictory `R`;
///   * `false` — `FingerPrintDef::parseTestStr`, used inside a `MatchPoints` block,
///     where every value is a *point count* (so `R=100` is normal and must not be run
///     through the Y/N logic).
fn parse_test_line(
    line: &str,
    lineno: usize,
    apply_r_defaults: bool,
    warnings: &mut Vec<DbWarning>,
) -> Option<FingerTest> {
    let open = line.find('(')?;
    let name = &line[..open];
    let Some(id) = TestId::from_name(name) else {
        warnings.push(DbWarning {
            line: lineno,
            message: format!("unknown fingerprint test {name:?}"),
        });
        return None;
    };
    let Some(close) = line[open..].find(')').map(|i| open.saturating_add(i)) else {
        warnings.push(DbWarning {
            line: lineno,
            message: format!("test {name} has no closing ')'"),
        });
        return None;
    };
    let body = line.get(open.saturating_add(1)..close).unwrap_or_default();

    let mut test = FingerTest::new(id);
    // The C's special case: a test without an R attribute may still be written "R=N" to
    // say "no response", which yields an entirely empty test.
    if apply_r_defaults && !id.has_r() && body == "R=N" {
        return Some(test);
    }

    let mut max_idx = 0usize;
    let mut any = false;
    if !body.is_empty() {
        for field in body.split('%') {
            let Some(eq) = field.find('=') else {
                warnings.push(DbWarning {
                    line: lineno,
                    message: format!("test {name}: attribute {field:?} has no '='"),
                });
                return None;
            };
            let (attr, value) = (
                &field[..eq],
                field.get(eq.saturating_add(1)..).unwrap_or_default(),
            );
            let Some(idx) = id.attr_index(attr) else {
                warnings.push(DbWarning {
                    line: lineno,
                    message: format!("test {name}: unknown attribute {attr:?}"),
                });
                return None;
            };
            if test.values[idx].is_some() {
                warnings.push(DbWarning {
                    line: lineno,
                    message: format!("test {name}: duplicate attribute {attr:?}"),
                });
                return None;
            }
            test.values[idx] = Some(value.to_owned());
            max_idx = max_idx.max(idx);
            any = true;
        }
    }

    // The C's post-processing of the R attribute: a test that specified other attributes
    // implicitly responded (R=Y); one that specified nothing did not (R=N). Only the
    // fingerprint-record parser does this — see `apply_r_defaults`.
    if apply_r_defaults && id.has_r() {
        if any && max_idx > 0 {
            match test.values[0].as_deref() {
                None => test.values[0] = Some("Y".to_owned()),
                Some(r) if r.contains('Y') => {}
                Some(r) => {
                    warnings.push(DbWarning {
                        line: lineno,
                        message: format!("test {name}: has attributes but R={r}"),
                    });
                    return None;
                }
            }
        } else if test.values[0].is_none() {
            test.values[0] = Some("N".to_owned());
        }
    }
    Some(test)
}

/// Parse a `Class vendor | family | generation | device type` line.
fn parse_class_line(rest: &str, lineno: usize, warnings: &mut Vec<DbWarning>) -> Option<OsClass> {
    // A line that is only separators/blanks is silently ignored by the C.
    if rest
        .trim_matches(|c: char| c == '|' || c.is_whitespace())
        .is_empty()
    {
        return None;
    }
    let parts: Vec<&str> = rest.splitn(4, '|').collect();
    if parts.len() < 4 {
        warnings.push(DbWarning {
            line: lineno,
            message: format!(
                "Class line needs 4 '|'-separated fields, got {}",
                parts.len()
            ),
        });
        return None;
    }
    let generation = parts[2].trim();
    Some(OsClass {
        vendor: parts[0].trim().to_owned(),
        family: parts[1].trim().to_owned(),
        // The C stores NULL rather than "" for a blank generation.
        generation: (!generation.is_empty()).then(|| generation.to_owned()),
        device_type: parts[3].trim().to_owned(),
        cpe: Vec::new(),
    })
}

impl FingerPrintDb {
    /// Parse a whole `nmap-os-db`.
    ///
    /// Never fails: unparseable lines are recorded in [`FingerPrintDb::warnings`] and
    /// skipped. On the shipped database this produces zero warnings.
    #[must_use]
    pub fn parse(text: &str) -> FingerPrintDb {
        let mut db = FingerPrintDb::default();
        let mut current: Option<FingerPrint> = None;
        let mut parsing_match_points = false;

        for (i, raw) in text.lines().enumerate() {
            let lineno = i.saturating_add(1);
            // Strip a trailing comment, then surrounding whitespace, as the C does when
            // it looks for the "\n#" terminator.
            let line = match raw.find('#') {
                Some(0) => continue,
                Some(h) => raw[..h].trim_end(),
                None => raw.trim_end(),
            };
            if line.trim().is_empty() {
                continue;
            }

            if let Some(rest) = line.strip_prefix("Fingerprint") {
                // Finish the previous record before starting a new one.
                if let Some(fp) = current.take() {
                    db.prints.push(fp);
                }
                parsing_match_points = false;
                let name = rest.trim();
                if name.is_empty() {
                    // C: fatal("Parse error on line %d of fingerprint")
                    db.warnings.push(DbWarning {
                        line: lineno,
                        message: "Fingerprint line has an empty OS name".to_owned(),
                    });
                    continue;
                }
                current = Some(FingerPrint {
                    os_name: name.to_owned(),
                    line: lineno,
                    ..FingerPrint::default()
                });
            } else if line.starts_with("MatchPoints") {
                if let Some(fp) = current.take() {
                    db.prints.push(fp);
                }
                if db.match_points.is_some() {
                    // C: fatal(...) on a second MatchPoints block.
                    db.warnings.push(DbWarning {
                        line: lineno,
                        message: "duplicate MatchPoints block; ignoring the second".to_owned(),
                    });
                    parsing_match_points = false;
                    continue;
                }
                db.match_points = Some(MatchPoints::default());
                parsing_match_points = true;
            } else if line.starts_with("This nmap-os-db") {
                // A version banner; the C only warns if it looks newer than itself.
                continue;
            } else if parsing_match_points {
                // Inside MatchPoints every line is TEST(attr=points%...).
                let Some(test) = parse_test_line(line, lineno, false, &mut db.warnings) else {
                    continue;
                };
                let Some(mp) = db.match_points.as_mut() else {
                    continue;
                };
                for (idx, value) in test.values.iter().enumerate() {
                    let Some(v) = value else { continue };
                    match v.trim().parse::<u32>() {
                        // C: fatal() when points <= 0 or unparseable.
                        Ok(points) if points > 0 => {
                            mp.set(test.id, idx, points);
                        }
                        _ => db.warnings.push(DbWarning {
                            line: lineno,
                            message: format!(
                                "MatchPoints {}: attribute value {v:?} is not a positive integer",
                                test.id.name()
                            ),
                        }),
                    }
                }
            } else if let Some(rest) = line.strip_prefix("Class ") {
                let Some(fp) = current.as_mut() else {
                    db.warnings.push(DbWarning {
                        line: lineno,
                        message: "Class line outside a Fingerprint record".to_owned(),
                    });
                    continue;
                };
                if let Some(class) = parse_class_line(rest, lineno, &mut db.warnings) {
                    fp.classes.push(class);
                }
            } else if let Some(rest) = line.strip_prefix("CPE ") {
                // The CPE may be followed by whitespace-separated flags (e.g. "auto"),
                // which the C discards.
                let Some(cpe) = rest.split_whitespace().next() else {
                    continue;
                };
                match current.as_mut().and_then(|fp| fp.classes.last_mut()) {
                    Some(class) => class.cpe.push(cpe.to_owned()),
                    // C: fatal("\"CPE\" line without preceding \"Class\"")
                    None => db.warnings.push(DbWarning {
                        line: lineno,
                        message: "CPE line without a preceding Class line".to_owned(),
                    }),
                }
            } else if let Some(fp) = current.as_mut() {
                let Some(test) = parse_test_line(line, lineno, true, &mut db.warnings) else {
                    continue;
                };
                // Points available for this test = the sum of the match-point weights of
                // the attributes it actually specifies.
                if let Some(mp) = db.match_points.as_ref() {
                    for (idx, value) in test.values.iter().enumerate() {
                        if value.is_some() {
                            fp.num_points = fp.num_points.saturating_add(mp.get(test.id, idx));
                        }
                    }
                }
                fp.tests.push(test);
            } else {
                db.warnings.push(DbWarning {
                    line: lineno,
                    message: format!("unrecognized line outside any record: {line:?}"),
                });
            }
        }

        if let Some(fp) = current.take() {
            db.prints.push(fp);
        }
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "# a comment\n",
        "MatchPoints\n",
        "SEQ(SP=25%GCD=75%ISR=25)\n",
        "T1(R=100%DF=20%T=15)\n",
        "\n",
        "Fingerprint Linux 5.4\n",
        "Class Linux | Linux | 5.X | general purpose\n",
        "CPE cpe:/o:linux:linux_kernel:5 auto\n",
        "SEQ(SP=100-10A%GCD=1-6%ISR=105-10F)\n",
        "T1(R=Y%DF=Y%T=3B-45)\n",
        "\n",
        "Fingerprint Some Router\n",
        "Class Cisco | IOS | 12.X | router\n",
        "T1(R=N)\n",
    );

    #[test]
    fn parses_records_classes_and_tests() {
        let db = FingerPrintDb::parse(SAMPLE);
        assert!(db.warnings.is_empty(), "warnings: {:?}", db.warnings);
        assert_eq!(db.prints.len(), 2);
        assert!(db.match_points.is_some());

        let linux = &db.prints[0];
        assert_eq!(linux.os_name, "Linux 5.4");
        assert_eq!(linux.classes.len(), 1);
        assert_eq!(linux.classes[0].vendor, "Linux");
        assert_eq!(linux.classes[0].generation.as_deref(), Some("5.X"));
        assert_eq!(linux.classes[0].device_type, "general purpose");
        assert_eq!(linux.classes[0].cpe, vec!["cpe:/o:linux:linux_kernel:5"]);
        assert_eq!(linux.tests.len(), 2);
        assert_eq!(linux.test(TestId::Seq).unwrap().get("SP"), Some("100-10A"));
        assert_eq!(linux.test(TestId::T1).unwrap().get("T"), Some("3B-45"));
    }

    #[test]
    fn match_points_drive_the_available_point_total() {
        let db = FingerPrintDb::parse(SAMPLE);
        let mp = db.match_points.as_ref().unwrap();
        assert_eq!(
            mp.get(TestId::Seq, TestId::Seq.attr_index("SP").unwrap()),
            25
        );
        assert_eq!(mp.get(TestId::T1, TestId::T1.attr_index("R").unwrap()), 100);
        // Linux specifies SEQ SP/GCD/ISR (25+75+25) and T1 R/DF/T (100+20+15).
        assert_eq!(db.prints[0].num_points, 25 + 75 + 25 + 100 + 20 + 15);
    }

    #[test]
    fn r_attribute_defaults_follow_the_c() {
        let db = FingerPrintDb::parse(SAMPLE);
        // Explicit R=N stays N and leaves the rest unset.
        let router_t1 = db.prints[1].test(TestId::T1).unwrap();
        assert_eq!(router_t1.get("R"), Some("N"));
        assert_eq!(router_t1.get("DF"), None);

        // A test with attributes but no explicit R gets R=Y.
        let db2 = FingerPrintDb::parse("Fingerprint X\nT1(DF=Y%T=40)\n");
        assert_eq!(db2.prints[0].test(TestId::T1).unwrap().get("R"), Some("Y"));

        // A test whose R contradicts its attributes is rejected with a warning.
        let db3 = FingerPrintDb::parse("Fingerprint X\nT1(R=N%DF=Y)\n");
        assert!(db3.prints[0].tests.is_empty());
        assert_eq!(db3.warnings.len(), 1);
    }

    #[test]
    fn seq_style_tests_accept_the_bare_r_n_form() {
        // SEQ has no R attribute, but "R=N" is still accepted as "nothing observed".
        let db = FingerPrintDb::parse("Fingerprint X\nSEQ(R=N)\n");
        assert!(db.warnings.is_empty(), "{:?}", db.warnings);
        let seq = db.prints[0].test(TestId::Seq).unwrap();
        assert!(seq.values.iter().all(Option::is_none));
    }

    #[test]
    fn malformed_lines_warn_and_skip_rather_than_abort() {
        let db = FingerPrintDb::parse(concat!(
            "Fingerprint Good One\n",
            "NOPE(R=Y)\n",      // unknown test
            "SEQ(SP\n",         // no ')'
            "SEQ(ZZ=1)\n",      // unknown attribute
            "SEQ(SP=1%SP=2)\n", // duplicate attribute
            "T1(R=Y%DF=Y)\n",   // this one is fine
        ));
        assert_eq!(db.prints.len(), 1, "the record survives");
        assert_eq!(db.prints[0].tests.len(), 1, "only the good test is kept");
        assert_eq!(db.warnings.len(), 4);
        assert!(db.warnings.iter().all(|w| w.line >= 2));
    }

    #[test]
    fn structural_problems_the_c_fatals_on_are_only_warnings() {
        // Duplicate MatchPoints.
        let db = FingerPrintDb::parse("MatchPoints\nSEQ(SP=1)\nMatchPoints\nSEQ(SP=2)\n");
        assert!(db.match_points.is_some());
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("duplicate MatchPoints")));

        // CPE with no Class.
        let db = FingerPrintDb::parse("Fingerprint X\nCPE cpe:/o:x\n");
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("without a preceding Class")));

        // Class with too few fields.
        let db = FingerPrintDb::parse("Fingerprint X\nClass A | B\n");
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("4 '|'-separated fields")));

        // Empty OS name.
        let db = FingerPrintDb::parse("Fingerprint    \n");
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("empty OS name")));
    }

    #[test]
    fn is_total_on_hostile_input() {
        for src in [
            "",
            "\n\n\n",
            "#",
            "Fingerprint",
            "Fingerprint\n",
            "MatchPoints",
            "Class",
            "CPE",
            "SEQ(",
            "SEQ)",
            "()",
            "(",
            ")",
            "=",
            "%",
            "Fingerprint X\nSEQ(=)\n",
            "Fingerprint X\nSEQ(%%%%)\n",
            "Fingerprint X\n(SP=1)\n",
            "MatchPoints\nSEQ(SP=notanumber)\n",
            "MatchPoints\nSEQ(SP=-5)\n",
            "MatchPoints\nSEQ(SP=0)\n",
            "This nmap-os-db",
            "\u{0}\u{1}\u{2}",
            "Fingerprint \u{1f600}\nSEQ(SP=1)\n",
        ] {
            let db = FingerPrintDb::parse(src);
            // The contract is that it returns; touch the result so nothing is elided.
            let _ = db.prints.len() + db.warnings.len();
        }
    }

    #[test]
    fn a_blank_generation_is_none_not_empty() {
        let db = FingerPrintDb::parse("Fingerprint X\nClass Apple | macOS |  | general purpose\n");
        assert_eq!(db.prints[0].classes[0].generation, None);
    }
}
