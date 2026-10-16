//! Which files an NSE script may open (Decision 2, `docs/M6-ANALYSIS.md`).
//!
//! nmap gives every script the whole file system, with the privileges nmap
//! runs under — usually root. Measured across the 744 shipped Lua files, what
//! scripts open is: data files nmap ships (found with `nmap.fetchfile`), files
//! the operator names in `--script-args` (`userdb=`, `passdb=`, output files),
//! and nothing else. So that is what is allowed:
//!
//! - **reading** a file beneath one of nmap's data directories, or a file the
//!   operator named in an argument a shipped script reads as a local file
//!   ([`READ_FILE_ARGS`], [`WRITE_FILE_ARGS`]);
//! - **writing** a file the operator named in an argument a shipped script
//!   writes ([`WRITE_FILE_ARGS`]), or one beneath a directory the operator
//!   designated for script output ([`OUTPUT_DIR_ARGS`]).
//!
//! A value under any other argument names nothing a script may open: until
//! D2 every value that named a local file did, so a path on the target
//! (`http-phpmyadmin-dir-traversal.file=/etc/passwd`) handed this host's file
//! to every script (`nse-named-values-grant-files`, now
//! `nse-file-args-documented`).
//!
//! A directory is designated for output by the operator naming it in one of
//! the arguments the shipped scripts document as an output directory
//! ([`OUTPUT_DIR_ARGS`], `docs/LFS-ANALYSIS.md` D1), and only there: a value
//! elsewhere that happens to name a directory (`url=/`) designates nothing.
//! Directories are created ([`FsPolicy::allows_mkdir`], `lfs.mkdir`) beneath
//! a designated directory and nowhere else.
//!
//! Every path is compared after canonicalisation — the host resolves `..`,
//! `.` and symbolic links before asking, and names the file it would open —
//! so neither `../../etc/shadow` nor a link planted in a data directory gets
//! out. A refusal looks to the script like the system refusing:
//! `nil, "NAME: Permission denied", 13`.

use std::path::{Path, PathBuf};

/// The directories and files a run allows, each canonical.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsPolicy {
    /// nmap's data directories (`--datadir`, `NMAPDIR`, `~/.nmap`, the
    /// install directory): readable, with everything beneath them.
    pub read_roots: Vec<PathBuf>,
    /// Directories the operator designated for script output: readable and
    /// writable, with everything beneath them.
    pub write_roots: Vec<PathBuf>,
    /// Files the operator named in an argument a shipped script writes
    /// ([`WRITE_FILE_ARGS`]): readable and writable.
    pub named: Vec<PathBuf>,
    /// Files the host makes readable and nothing more: the operator's
    /// `~/.ssh/config` and `~/.ssh/known_hosts`, which `ssh1.lua` reads
    /// through `os.getenv("HOME")` (`os-getenv-home-only`).
    pub read_named: Vec<PathBuf>,
    /// Directories a script may create although they are not beneath an
    /// output directory: the missing components of an output directory the
    /// operator named before it existed, from its nearest existing ancestor
    /// down (`/tmp/new` for `destination=/tmp/new/dest`), as nmap's
    /// http-fetch creates them.
    pub creatable: Vec<PathBuf>,
}

impl FsPolicy {
    /// Whether a script may create the directory at `canonical`: beneath a
    /// designated output directory, or one of the missing directories on the
    /// way to one (a named *file* is a file).
    pub fn allows_mkdir(&self, canonical: &Path) -> bool {
        canonical.is_absolute()
            && (self.write_roots.iter().any(|r| canonical.starts_with(r))
                || self.creatable.iter().any(|c| c == canonical))
    }

    /// Whether a script may open the file at `canonical` — for writing too
    /// when `write` is set.
    pub fn allows(&self, canonical: &Path, write: bool) -> bool {
        if !canonical.is_absolute() {
            return false;
        }
        let beneath = |roots: &[PathBuf]| roots.iter().any(|r| canonical.starts_with(r));
        if self.named.iter().any(|n| n == canonical) || beneath(&self.write_roots) {
            return true;
        }
        !write && (beneath(&self.read_roots) || self.read_named.iter().any(|n| n == canonical))
    }
}

/// The script arguments that designate an output directory: those the
/// shipped scripts document as the directory they save into, by their full
/// key, and by the short key `stdnse.get_script_args` also accepts
/// (`stdnse.lua:616-628`) only where no other shipped script reads that short
/// key. `dir` is not one: `http-phpmyadmin-dir-traversal.dir` and
/// `http-vlcstreamer-ls.dir` are paths on the target, so `dir=/` would
/// otherwise make this host's root writable. Nor is `save`, which
/// `stuxnet-detect` reads as a file-name template, nor `path`, which 34
/// script keys end in, most of them URL paths on the target.
pub const OUTPUT_DIR_ARGS: [&str; 12] = [
    "http-fetch.destination", // http-fetch.nse:200
    "destination",
    "http-config-backup.save",  // http-config-backup.nse:183
    "ms-sql-dump-hashes.dir",   // ms-sql-dump-hashes.nse:98
    "snmp-ios-config.tftproot", // snmp-ios-config.nse:55
    "tftproot",
    "cics-enum.path",                    // cics-enum.nse:378
    "lu-enum.path",                      // lu-enum.nse:178
    "vtam-enum.path",                    // vtam-enum.nse:249
    "domino-enum-users.path",            // domino-enum-users.nse:74
    "http-domino-enum-passwords.idpath", // http-domino-enum-passwords.nse:217
    "idpath",
];

/// The script arguments whose value the shipped scripts and libraries open
/// as a local file for reading, and nothing more (D2, `docs/LFS-ANALYSIS.md`
/// §8): by full key, and by the short key `stdnse.get_script_args` also
/// accepts where every shipped reader of that short key reads a local file.
/// `file` is not one: `http-axis2-dir-traversal.file`,
/// `http-phpmyadmin-dir-traversal.file` and `http-vuln-cve2006-3392.file`
/// name a file on the target. `filename` is read-only here though
/// `ajp-request.filename` writes, so only its full key writes. Arguments read
/// through `nmap.fetchfile` alone (`datafiles`, `jdwp-inject.filename`) never
/// leave the data directories and need no grant.
pub const READ_FILE_ARGS: [&str; 52] = [
    "userdb",         // nselib/unpwdb.lua:84 (registry: no short form)
    "passdb",         // nselib/unpwdb.lua:93
    "brute.credfile", // nselib/brute.lua:1027
    "credfile",
    "broadcast-igmp-discovery.mgroupnamesdb", // broadcast-igmp-discovery.nse:315
    "mgroupnamesdb",
    "idlist",             // cics-enum.nse:377, vtam-enum.nse:248
    "lulist",             // lu-enum.nse:177
    "clamav-exec.scandb", // clamav-exec.nse:148
    "scandb",
    "cvs-brute-repository.repofile", // cvs-brute-repository.nse:96
    "repofile",
    "dns-brute.hostlist",      // dns-brute.nse:229
    "nje-node-brute.hostlist", // nje-node-brute.nse:158
    "hostlist",
    "dns-brute.srvlist", // dns-brute.nse:275
    "srvlist",
    "folderdb",                        // http-iis-webdav-vuln.nse:116 (registry)
    "http-put.file",                   // http-put.nse:40; not `file`
    "http-sql-injection.errorstrings", // http-sql-injection.nse:229
    "errorstrings",
    "http-stored-xss.dbfile", // http-stored-xss.nse:150
    "dbfile",
    "http-vhosts.filelist", // http-vhosts.nse:62
    "filelist",
    "http-virustotal.filename", // http-virustotal.nse:99
    "smb-print-text.filename",  // smb-print-text.nse:45
    "filename",
    "ip-geolocation-maxmind.maxmind_db", // ip-geolocation-maxmind.nse:49
    "maxmind_db",
    "mikrotik-routeros-username-brute.wordlist", // mikrotik-routeros-username-brute.nse:86
    "wordlist",
    "oraclesids",              // oracle-sid-brute.nse:136 (registry)
    "puppet-naivesigning.csr", // puppet-naivesigning.nse:117
    "csr",
    "rtsp-url-brute.urlfile", // rtsp-url-brute.nse:122
    "urlfile",
    "sip-enum-users.userslist", // sip-enum-users.nse:229
    "userslist",
    "snmp-brute.communitiesdb", // snmp-brute.nse:113
    "communitiesdb",
    "ssh-hostkey.known-hosts", // ssh-hostkey.nse:361
    "known-hosts",
    "publickeydb",                   // ssh-publickey-acceptance.nse:48
    "ssl-known-key.fingerprintfile", // ssl-known-key.nse:113
    "fingerprintfile",
    "targets-ipv6-eui64.input", // targets-ipv6-eui64.nse:44
    "input",
    "targets-xml.iX", // targets-xml.nse:36
    "iX",
    "bittorrent-discovery.torrent", // bittorrent-discovery.nse:51
    "torrent",
];

/// The script arguments whose value the shipped scripts open as a local file
/// for writing, or appending: readable and writable (D2). Full keys, and
/// short keys every shipped reader of which writes a local file.
pub const WRITE_FILE_ARGS: [&str; 20] = [
    "ajp-request.filename",                  // ajp-request.nse:52
    "http-awstatstotals-exec.outfile",       // http-awstatstotals-exec.nse:97
    "http-axis2-dir-traversal.outfile",      // http-axis2-dir-traversal.nse:121
    "http-majordomo2-dir-traversal.outfile", // http-majordomo2-dir-traversal.nse:71
    "http-phpmyadmin-dir-traversal.outfile", // http-phpmyadmin-dir-traversal.nse:100
    "http-tplink-dir-traversal.outfile",     // http-tplink-dir-traversal.nse:114
    "shodan-api.outfile",                    // shodan-api.nse:80
    "url-snarf.outfile",                     // url-snarf.nse:86 (append)
    "outfile",
    "http-wordpress-users.out", // http-wordpress-users.nse:114
    "supermicro-ipmi-conf.out", // supermicro-ipmi-conf.nse:66
    "out",
    "ip-geolocation-map-bing.map_path", // ip-geolocation-map-bing.nse:156
    "ip-geolocation-map-google.map_path", // ip-geolocation-map-google.nse:138
    "ip-geolocation-map-kml.map_path",  // ip-geolocation-map-kml.nse:66
    "map_path",
    "oracle-brute-stealth.johnfile", // oracle-brute-stealth.nse:63
    "johnfile",
    "traceroute-geolocation.kmlfile", // traceroute-geolocation.nse:71
    "kmlfile",
];

/// The string values of the top-level arguments whose keys `keys` lists.
/// `nmap.registry.args[k]` and `stdnse.get_script_args` read top-level
/// fields only, so nothing nested or in the array part is a path a script
/// opens from its arguments.
fn values_of(args: &super::scriptargs::ArgTable, keys: &[&str]) -> Vec<Vec<u8>> {
    use super::scriptargs::ArgValue;
    args.fields
        .iter()
        .filter(|(k, _)| keys.iter().any(|a| a.as_bytes() == k.as_slice()))
        .filter_map(|(_, v)| match v {
            ArgValue::Str(s) => Some(s.clone()),
            ArgValue::Table(_) => None,
        })
        .collect()
}

/// The directories the operator designated for output: the values of the
/// arguments [`OUTPUT_DIR_ARGS`] names.
pub fn output_dir_values(args: &super::scriptargs::ArgTable) -> Vec<Vec<u8>> {
    values_of(args, &OUTPUT_DIR_ARGS)
}

/// The files the operator named for scripts to read: [`READ_FILE_ARGS`].
pub fn read_file_values(args: &super::scriptargs::ArgTable) -> Vec<Vec<u8>> {
    values_of(args, &READ_FILE_ARGS)
}

/// The files the operator named for scripts to write: [`WRITE_FILE_ARGS`].
pub fn write_file_values(args: &super::scriptargs::ArgTable) -> Vec<Vec<u8>> {
    values_of(args, &WRITE_FILE_ARGS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FsPolicy {
        FsPolicy {
            read_roots: vec![PathBuf::from("/usr/share/nmap")],
            write_roots: vec![PathBuf::from("/home/op/loot")],
            named: vec![PathBuf::from("/home/op/users.txt")],
            read_named: vec![PathBuf::from("/home/op/.ssh/known_hosts")],
            creatable: vec![PathBuf::from("/home/op/pending")],
        }
    }

    #[test]
    fn read_named_files_are_readable_not_writable() {
        let p = policy();
        assert!(p.allows(Path::new("/home/op/.ssh/known_hosts"), false));
        assert!(!p.allows(Path::new("/home/op/.ssh/known_hosts"), true));
        assert!(!p.allows(Path::new("/home/op/.ssh/known_hosts/x"), false));
    }

    #[test]
    fn data_files_are_readable_not_writable() {
        let p = policy();
        assert!(p.allows(
            Path::new("/usr/share/nmap/nselib/data/passwords.lst"),
            false
        ));
        assert!(!p.allows(Path::new("/usr/share/nmap/nselib/data/passwords.lst"), true));
    }

    #[test]
    fn named_files_and_output_dirs_are_both() {
        let p = policy();
        assert!(p.allows(Path::new("/home/op/users.txt"), false));
        assert!(p.allows(Path::new("/home/op/users.txt"), true));
        assert!(p.allows(Path::new("/home/op/loot/http/index.html"), true));
    }

    #[test]
    fn everything_else_is_refused() {
        let p = policy();
        for path in [
            "/etc/shadow",
            "/home/op/.ssh/id_rsa",
            "/usr/share/nmapx/f",
            "/home/op/lootx",
        ] {
            assert!(!p.allows(Path::new(path), false), "{path}");
            assert!(!p.allows(Path::new(path), true), "{path}");
        }
        // A named file names that file, not its directory.
        assert!(!p.allows(Path::new("/home/op/users.txt/x"), false));
        // Relative paths are never canonical.
        assert!(!p.allows(Path::new("nselib/data/x"), false));
    }

    #[test]
    fn directories_are_made_beneath_output_dirs_only() {
        let p = policy();
        assert!(p.allows_mkdir(Path::new("/home/op/loot/10.0.0.1")));
        assert!(p.allows_mkdir(Path::new("/home/op/loot/a/b")));
        // Not beside it, not in a data directory, not where a file is named.
        for path in [
            "/home/op/lootx",
            "/home/op/new",
            "/usr/share/nmap/scripts/x",
            "/home/op/users.txt",
            "/home/op/.ssh/known_hosts",
            "loot/x",
        ] {
            assert!(!p.allows_mkdir(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn the_missing_way_to_an_output_dir_is_creatable_and_no_more() {
        let p = policy();
        assert!(p.allows_mkdir(Path::new("/home/op/pending")));
        // Only the directory itself: not a file there, nor beneath it.
        assert!(!p.allows(Path::new("/home/op/pending"), true));
        assert!(!p.allows_mkdir(Path::new("/home/op/pending/other")));
        assert!(!p.allows_mkdir(Path::new("/home/op/pendingx")));
    }

    #[test]
    fn only_documented_output_arguments_designate_directories() {
        use crate::nse::scriptargs::registry_args;
        let args = registry_args(
            None,
            b"http-fetch.destination=/a,destination=/b,tftproot=/c,ms-sql-dump-hashes.dir=/d,\
              http-config-backup.save=/e,snmp-ios-config.tftproot=/f,dir=/,save=/g,url=/,\
              x.destination=/h,{/i},nested={destination=/j},http-fetch.destination2=/k,\
              cics-enum.path=/l,lu-enum.path=/m,vtam-enum.path=/n,domino-enum-users.path=/o,\
              http-domino-enum-passwords.idpath=/p,idpath=/q,path=/,\
              http-domino-enum-passwords.path=/r",
        )
        .expect("parses");
        assert_eq!(
            output_dir_values(&args),
            ["/a", "/b", "/c", "/d", "/e", "/f", "/l", "/m", "/n", "/o", "/p", "/q"]
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        );
        // A table value designates nothing.
        let args = registry_args(None, b"destination={/a,/b}").expect("parses");
        assert!(output_dir_values(&args).is_empty());
    }

    /// D2: a value grants a file only from an argument a shipped script
    /// opens as a local file, reading or writing as that script does.
    #[test]
    fn only_local_file_arguments_name_files() {
        use crate::nse::scriptargs::registry_args;
        let s = |v: &[&str]| v.iter().map(|x| x.as_bytes().to_vec()).collect::<Vec<_>>();
        let args = registry_args(
            None,
            b"userdb=/u,brute.credfile=/c,credfile=/c2,http-put.file=/p,filename=/f,\
              http-virustotal.filename=/v,smb-print-text.filename=/s,\
              ajp-request.filename=/aw,outfile=/o,url-snarf.outfile=/us,out=/w,map_path=/m,\
              http-phpmyadmin-dir-traversal.file=/etc/passwd,file=/etc/shadow,\
              http-axis2-dir-traversal.file=/x,url=/,path=/tmp,dir=/,\
              nested={userdb=/n},{/arr},x.userdb=/xu",
        )
        .expect("parses");
        assert_eq!(
            read_file_values(&args),
            s(&["/u", "/c", "/c2", "/p", "/f", "/v", "/s"])
        );
        assert_eq!(
            write_file_values(&args),
            s(&["/aw", "/o", "/us", "/w", "/m"])
        );
        let all: Vec<Vec<u8>> = read_file_values(&args)
            .into_iter()
            .chain(write_file_values(&args))
            .chain(output_dir_values(&args))
            .collect();
        for remote in [
            "/etc/passwd",
            "/etc/shadow",
            "/x",
            "/",
            "/tmp",
            "/n",
            "/arr",
            "/xu",
        ] {
            assert!(
                !all.contains(&remote.as_bytes().to_vec()),
                "{remote} was granted"
            );
        }
    }

    /// No key is in two tables: each grants one kind of access.
    #[test]
    fn the_tables_are_disjoint() {
        for k in READ_FILE_ARGS {
            assert!(!WRITE_FILE_ARGS.contains(&k), "{k}");
            assert!(!OUTPUT_DIR_ARGS.contains(&k), "{k}");
        }
        for k in WRITE_FILE_ARGS {
            assert!(!OUTPUT_DIR_ARGS.contains(&k), "{k}");
        }
        for k in [
            "file", "path", "dir", "save", "url", "uri", "rfile", "basepath",
        ] {
            assert!(
                !READ_FILE_ARGS.contains(&k)
                    && !WRITE_FILE_ARGS.contains(&k)
                    && !OUTPUT_DIR_ARGS.contains(&k),
                "{k}"
            );
        }
    }

    #[test]
    fn prefixes_are_components_not_bytes() {
        let p = policy();
        assert!(!p.allows(Path::new("/usr/share/nmap-evil/x"), false));
        assert!(!p.allows(Path::new("/home/op/loot2/x"), true));
    }
}
