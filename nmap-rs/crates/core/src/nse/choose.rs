//! Which scripts a run loads: `get_chosen_scripts` (`nse_main.lua:717`),
//! less the loading itself, which `nse_main.lua`'s own `Script.new` does
//! ([`super::engine::NseState::load_scripts`]).
//!
//! The selection grammar is [`super::selection`] (M6.2); this is the loop
//! around it. Each script in `script.db`, in index order, is tested against
//! every rule; the first rule that selects it decides how it was selected,
//! and every rule that selects it is marked used. A rule that selected
//! nothing is then tried as a script's file name, with and without `.nse`,
//! and as a directory, and is an error if it is none of those.
//!
//! Two orders the C leaves to chance are fixed here (`nse-chosen-order`):
//! the leftover rules are tried in the order they were given, where the C
//! walks them in a Lua table's hash order, and a directory's scripts load in
//! name order, where the C takes the order `readdir` returns.

use super::engine::ChosenScript;
use super::script::ScriptDb;
use super::selection::{matches, normalize, Entry, SelectionError};

/// What [`ScriptLocator::fetch_script`] found: `nse_fetchscript`'s file (1)
/// and directory (2) results, a directory named without a trailing `/`
/// distinguished as the C's `nse_fetch` distinguishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    File(Vec<u8>),
    Directory(Vec<u8>),
    BareDirectory(Vec<u8>),
}

/// The file system as script selection sees it.
pub trait ScriptLocator {
    /// `nse_fetchscript`: `name` as an absolute path, else under a data
    /// directory's `scripts/`, else relative to the working directory.
    fn fetch_script(&self, name: &[u8]) -> Option<Found>;
    /// `lfs.dir(path)`: the names in a directory.
    fn list_dir(&self, path: &[u8]) -> Vec<Vec<u8>>;
}

/// What selection decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chosen {
    /// The scripts to load, in the order the C loads them.
    pub scripts: Vec<ChosenScript>,
    /// The warnings logged along the way (`log_error`), in order.
    pub warnings: Vec<Vec<u8>>,
    /// The error selection ended with, if it did. The C raises it once the
    /// scripts before it have been loaded, so a script that fails to load
    /// is reported first; load [`Chosen::scripts`], then report this.
    pub error: Option<Vec<u8>>,
}

/// The options `check_rules` reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleOptions {
    /// `-sC`: with no rules given, the rule is `default`.
    pub default: bool,
    /// `-sV`: the `version` category is added to the rules.
    pub version: bool,
}

/// `get_chosen_scripts(rules)`: the scripts the rules select from `db`.
pub fn choose(
    rules: &[Vec<u8>],
    options: RuleOptions,
    db: &ScriptDb,
    locate: &dyn ScriptLocator,
) -> Chosen {
    let mut out = Chosen::default();
    // `check_rules`.
    let mut given: Vec<Vec<u8>> = rules.to_vec();
    if options.default && given.is_empty() {
        given.push(b"default".to_vec());
    }
    if options.version {
        given.push(b"version".to_vec());
    }
    // The rule loop: each rule normalised in place, and recorded as unused.
    // A rule that normalises to nothing is left as given and recorded nowhere.
    let mut rules: Vec<Vec<u8>> = Vec::with_capacity(given.len());
    // (rule, used, forced), in first-given order; a later duplicate updates
    // `forced`, as the C's `forced_rules[rule] = ...` does.
    let mut used: Vec<(Vec<u8>, bool, bool)> = Vec::new();
    for raw in &given {
        match normalize(raw) {
            Some(r) => {
                let text = r.text.to_vec();
                match used.iter_mut().find(|(t, _, _)| *t == text) {
                    Some(entry) => {
                        entry.1 = false;
                        entry.2 = r.forced;
                    }
                    None => used.push((text.clone(), false, r.forced)),
                }
                rules.push(text);
            }
            None => rules.push(raw.clone()),
        }
    }
    let forced = |used: &[(Vec<u8>, bool, bool)], rule: &[u8]| {
        used.iter().any(|(t, _, f)| t.as_slice() == rule && *f)
    };
    let mut loaded: Vec<Vec<u8>> = Vec::new();
    // `script_database.chunk()`: `Entry` for each script in the index.
    'entries: for entry in db.entries() {
        let cats: Vec<&[u8]> = entry.categories().iter().map(Vec::as_slice).collect();
        let e = Entry::from_filename(entry.filename(), &cats);
        // `script_params`, shared by every rule of this entry.
        let mut verbosity = false;
        for rule in &rules {
            let sel = match matches(rule, &e) {
                Ok(s) => s,
                Err(SelectionError::NotAnExpression) => continue,
                Err(SelectionError::TooDeep) => {
                    out.error = Some(b"selection rule is nested too deeply".to_vec());
                    return out;
                }
                Err(SelectionError::TooLong) => {
                    out.error = Some(b"selection rule is too long".to_vec());
                    return out;
                }
            };
            if !sel.matched {
                continue;
            }
            if let Some(u) = used.iter_mut().find(|(t, _, _)| t == rule) {
                u.1 = true;
            }
            let selection = if sel.by_name {
                verbosity = true;
                "name"
            } else {
                "category"
            };
            match locate.fetch_script(entry.filename()) {
                Some(Found::File(path)) => {
                    if !loaded.contains(&path) {
                        out.scripts.push(ChosenScript {
                            path: path.clone(),
                            selection,
                            verbosity,
                            forced: forced(&used, rule),
                        });
                        loaded.push(path);
                    }
                }
                found => {
                    let path = match found {
                        Some(Found::Directory(p) | Found::BareDirectory(p)) => p,
                        _ => {
                            let mut m = b"no path to file/directory: ".to_vec();
                            m.extend_from_slice(entry.filename());
                            m
                        }
                    };
                    let mut w = b"Warning: Could not load '".to_vec();
                    w.extend_from_slice(entry.filename());
                    w.extend_from_slice(b"': ");
                    w.extend_from_slice(&path);
                    out.warnings.push(w);
                    continue 'entries;
                }
            }
        }
    }
    // The rules that selected nothing: files and directories.
    for (rule, was_used, is_forced) in used {
        if was_used {
            continue;
        }
        let found = locate.fetch_script(&rule).or_else(|| {
            let mut with_ext = rule.clone();
            with_ext.extend_from_slice(b".nse");
            locate.fetch_script(&with_ext)
        });
        match found {
            None => {
                if !(options.version && rule == b"version") {
                    let mut m = b"'".to_vec();
                    m.extend_from_slice(&rule);
                    m.extend_from_slice(b"' did not match a category, filename, or directory");
                    out.error = Some(m);
                    return out;
                }
            }
            Some(Found::BareDirectory(path)) => {
                let mut m = b"directory '".to_vec();
                m.extend_from_slice(&path);
                m.extend_from_slice(b"' found, but will not match without '/'");
                out.error = Some(m);
                return out;
            }
            Some(Found::File(path)) => {
                if !loaded.contains(&path) {
                    out.scripts.push(ChosenScript {
                        path: path.clone(),
                        selection: "file path",
                        verbosity: true,
                        forced: is_forced,
                    });
                    loaded.push(path);
                }
            }
            Some(Found::Directory(path)) => {
                let mut names = locate.list_dir(&path);
                names.sort();
                for name in names {
                    let mut file = path.clone();
                    file.push(b'/');
                    file.extend_from_slice(&name);
                    if file.ends_with(b".nse") && !loaded.contains(&file) {
                        out.scripts.push(ChosenScript {
                            path: file.clone(),
                            selection: "directory",
                            verbosity: false,
                            forced: is_forced,
                        });
                        loaded.push(file);
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nse::script::parse_script_db;

    struct Fake;

    impl ScriptLocator for Fake {
        fn fetch_script(&self, name: &[u8]) -> Option<Found> {
            let mut p = b"/data/scripts/".to_vec();
            p.extend_from_slice(name);
            match name {
                b"a.nse" | b"b.nse" | b"c.nse" | b"./mine.nse" => Some(Found::File(p)),
                b"dir/" => Some(Found::Directory(p)),
                b"dir" => Some(Found::BareDirectory(p)),
                _ => None,
            }
        }
        fn list_dir(&self, _: &[u8]) -> Vec<Vec<u8>> {
            vec![
                b"y.nse".to_vec(),
                b"z.nse".to_vec(),
                b"w.txt".to_vec(),
                b"x.nse".to_vec(),
            ]
        }
    }

    fn db() -> ScriptDb {
        parse_script_db(
            b"Entry { filename = \"a.nse\", categories = { \"default\", \"safe\", } }\n\
              Entry { filename = \"b.nse\", categories = { \"intrusive\", } }\n\
              Entry { filename = \"c.nse\", categories = { \"safe\", \"version\", } }\n",
        )
        .unwrap()
    }

    fn names(c: &Chosen) -> Vec<(String, &'static str, bool, bool)> {
        c.scripts
            .iter()
            .map(|s| {
                (
                    String::from_utf8_lossy(&s.path).into_owned(),
                    s.selection,
                    s.verbosity,
                    s.forced,
                )
            })
            .collect()
    }

    fn rules(rs: &[&str]) -> Vec<Vec<u8>> {
        rs.iter().map(|r| r.as_bytes().to_vec()).collect()
    }

    #[test]
    fn categories_and_names_in_index_order() {
        let c = choose(&rules(&["b", "safe"]), RuleOptions::default(), &db(), &Fake);
        assert_eq!(c.error, None);
        assert_eq!(
            names(&c),
            [
                ("/data/scripts/a.nse".into(), "category", false, false),
                ("/data/scripts/b.nse".into(), "name", true, false),
                ("/data/scripts/c.nse".into(), "category", false, false),
            ]
        );
    }

    #[test]
    fn default_version_and_forcing() {
        let c = choose(
            &[],
            RuleOptions {
                default: true,
                version: true,
            },
            &db(),
            &Fake,
        );
        assert_eq!(names(&c).len(), 2);
        let c = choose(&rules(&[" + safe "]), RuleOptions::default(), &db(), &Fake);
        assert!(c.scripts.iter().all(|s| s.forced));
    }

    #[test]
    fn files_directories_and_errors() {
        let c = choose(
            &rules(&["./mine", "dir/"]),
            RuleOptions::default(),
            &db(),
            &Fake,
        );
        assert_eq!(
            names(&c),
            [
                ("/data/scripts/./mine.nse".into(), "file path", true, false),
                ("/data/scripts/dir//x.nse".into(), "directory", false, false),
                ("/data/scripts/dir//y.nse".into(), "directory", false, false),
                ("/data/scripts/dir//z.nse".into(), "directory", false, false),
            ]
        );
        let c = choose(
            &rules(&["safe and not safe"]),
            RuleOptions::default(),
            &db(),
            &Fake,
        );
        assert_eq!(
            c.error.as_deref(),
            Some(&b"'safe and not safe' did not match a category, filename, or directory"[..])
        );
        let c = choose(&rules(&["dir"]), RuleOptions::default(), &db(), &Fake);
        assert!(c
            .error
            .unwrap()
            .starts_with(b"directory '/data/scripts/dir'"));
    }
}
