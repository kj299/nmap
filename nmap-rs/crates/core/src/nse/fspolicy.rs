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
//! `nse-file-args-documented`). The census behind the tables is `CENSUS` in
//! this module's tests, which checks each key against the line of the shipped
//! tree that reads it (`docs/LFS-ANALYSIS.md` §8).
//!
//! A directory is designated for output by the operator naming it in one of
//! the arguments the shipped scripts document as an output directory
//! ([`OUTPUT_DIR_ARGS`], `docs/LFS-ANALYSIS.md` D1), and only there: a value
//! elsewhere that happens to name a directory (`url=/`) designates nothing.
//! Directories are created ([`FsPolicy::allows_mkdir`], `lfs.mkdir`) beneath
//! a designated directory, or on the way to one named before it exists, and
//! nowhere else. The host grants nothing writable that overlaps what nmap
//! loads (`sys::nsefs`, `nse-write-overlapping-data-dirs`).
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
/// script keys end in, most of them URL paths on the target. Where each is
/// read: `CENSUS`, in the tests.
pub const OUTPUT_DIR_ARGS: [&str; 12] = [
    "http-fetch.destination",
    "destination",
    "http-config-backup.save",
    "ms-sql-dump-hashes.dir",
    "snmp-ios-config.tftproot",
    "tftproot",
    "cics-enum.path",
    "lu-enum.path",
    "vtam-enum.path",
    "domino-enum-users.path",
    "http-domino-enum-passwords.idpath",
    "idpath",
];

/// The script arguments whose value the shipped scripts and libraries open
/// as a local file for reading, and nothing more (D2, `docs/LFS-ANALYSIS.md`
/// §8): by full key, and by the short key `stdnse.get_script_args` also
/// accepts where every shipped reader of that short key opens a local file.
/// `file` is not one: `http-axis2-dir-traversal.file`,
/// `http-phpmyadmin-dir-traversal.file` and `http-vuln-cve2006-3392.file`
/// name a file on the target. `filename` is read-only here though
/// `ajp-request.filename` writes, so only that full key writes. An argument
/// a script looks up only with `nmap.fetchfile` (`datafiles`,
/// `tftp-enum.filelist`) is found beneath the data directories, which are
/// readable already, and one run with `loadfile` (`mysql-audit.filename`)
/// cannot be, as scripts have no `loadfile` here; neither is listed. Where
/// each is read: `CENSUS`, in the tests.
pub const READ_FILE_ARGS: [&str; 53] = [
    "userdb",
    "passdb",
    "brute.credfile",
    "credfile",
    "broadcast-igmp-discovery.mgroupnamesdb",
    "mgroupnamesdb",
    "idlist",
    "lulist",
    "clamav-exec.scandb",
    "scandb",
    "cvs-brute-repository.repofile",
    "repofile",
    "dns-brute.hostlist",
    "nje-node-brute.hostlist",
    "hostlist",
    "dns-brute.srvlist",
    "srvlist",
    "folderdb",
    "http-put.file",
    "http-sql-injection.errorstrings",
    "errorstrings",
    "http-stored-xss.dbfile",
    "dbfile",
    "http-vhosts.filelist",
    "filelist",
    "http-virustotal.filename",
    "jdwp-inject.filename",
    "smb-print-text.filename",
    "filename",
    "ip-geolocation-maxmind.maxmind_db",
    "maxmind_db",
    "mikrotik-routeros-username-brute.wordlist",
    "wordlist",
    "oraclesids",
    "puppet-naivesigning.csr",
    "csr",
    "rtsp-url-brute.urlfile",
    "urlfile",
    "sip-enum-users.userslist",
    "userslist",
    "snmp-brute.communitiesdb",
    "communitiesdb",
    "ssh-hostkey.known-hosts",
    "known-hosts",
    "publickeydb",
    "ssl-known-key.fingerprintfile",
    "fingerprintfile",
    "targets-ipv6-eui64.input",
    "input",
    "targets-xml.iX",
    "iX",
    "bittorrent-discovery.torrent",
    "torrent",
];

/// The script arguments whose value the shipped scripts open as a local file
/// for writing, or appending: readable and writable (D2). Full keys, and
/// short keys every shipped reader of which writes a local file. Where each
/// is read: `CENSUS`, in the tests.
pub const WRITE_FILE_ARGS: [&str; 20] = [
    "ajp-request.filename",
    "http-awstatstotals-exec.outfile",
    "http-axis2-dir-traversal.outfile",
    "http-majordomo2-dir-traversal.outfile",
    "http-phpmyadmin-dir-traversal.outfile",
    "http-tplink-dir-traversal.outfile",
    "shodan-api.outfile",
    "url-snarf.outfile",
    "outfile",
    "http-wordpress-users.out",
    "supermicro-ipmi-conf.out",
    "out",
    "ip-geolocation-map-bing.map_path",
    "ip-geolocation-map-google.map_path",
    "ip-geolocation-map-kml.map_path",
    "map_path",
    "oracle-brute-stealth.johnfile",
    "johnfile",
    "traceroute-geolocation.kmlfile",
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

    /// How a key's shipped reader uses the value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Opens {
        Read,
        Write,
        Dir,
    }
    use Opens::{Dir, Read, Write};

    /// The census (D2, `docs/LFS-ANALYSIS.md` §8): every key the tables list
    /// by its own name, the line of the shipped tree that reads it, and how
    /// what it names is opened there. A table's short keys are derived from
    /// these and checked against every reader in the tree
    /// ([`every_reader_of_a_short_key_opens_a_local_file`]).
    const CENSUS: &[(&str, &str, usize, Opens)] = &[
        ("http-fetch.destination", "scripts/http-fetch.nse", 200, Dir),
        (
            "http-config-backup.save",
            "scripts/http-config-backup.nse",
            183,
            Dir,
        ),
        (
            "ms-sql-dump-hashes.dir",
            "scripts/ms-sql-dump-hashes.nse",
            98,
            Dir,
        ),
        (
            "snmp-ios-config.tftproot",
            "scripts/snmp-ios-config.nse",
            55,
            Dir,
        ),
        ("cics-enum.path", "scripts/cics-enum.nse", 378, Dir),
        ("lu-enum.path", "scripts/lu-enum.nse", 178, Dir),
        ("vtam-enum.path", "scripts/vtam-enum.nse", 249, Dir),
        (
            "domino-enum-users.path",
            "scripts/domino-enum-users.nse",
            74,
            Dir,
        ),
        (
            "http-domino-enum-passwords.idpath",
            "scripts/http-domino-enum-passwords.nse",
            217,
            Dir,
        ),
        // `nmap.registry.args`: the key as written, no short form.
        ("userdb", "nselib/unpwdb.lua", 84, Read),
        ("passdb", "nselib/unpwdb.lua", 93, Read),
        ("brute.credfile", "nselib/brute.lua", 1027, Read),
        (
            "broadcast-igmp-discovery.mgroupnamesdb",
            "scripts/broadcast-igmp-discovery.nse",
            315,
            Read,
        ),
        ("idlist", "scripts/cics-enum.nse", 377, Read),
        ("idlist", "scripts/vtam-enum.nse", 248, Read),
        ("lulist", "scripts/lu-enum.nse", 177, Read),
        ("clamav-exec.scandb", "scripts/clamav-exec.nse", 148, Read),
        (
            "cvs-brute-repository.repofile",
            "scripts/cvs-brute-repository.nse",
            96,
            Read,
        ),
        ("dns-brute.hostlist", "scripts/dns-brute.nse", 229, Read),
        (
            "nje-node-brute.hostlist",
            "scripts/nje-node-brute.nse",
            158,
            Read,
        ),
        ("dns-brute.srvlist", "scripts/dns-brute.nse", 275, Read),
        ("folderdb", "scripts/http-iis-webdav-vuln.nse", 116, Read),
        ("http-put.file", "scripts/http-put.nse", 40, Read),
        (
            "http-sql-injection.errorstrings",
            "scripts/http-sql-injection.nse",
            229,
            Read,
        ),
        (
            "http-stored-xss.dbfile",
            "scripts/http-stored-xss.nse",
            150,
            Read,
        ),
        ("http-vhosts.filelist", "scripts/http-vhosts.nse", 62, Read),
        (
            "http-virustotal.filename",
            "scripts/http-virustotal.nse",
            99,
            Read,
        ),
        // `io.open(nmap.fetchfile(filename) or filename, "rb")`, line 55.
        ("jdwp-inject.filename", "scripts/jdwp-inject.nse", 51, Read),
        (
            "smb-print-text.filename",
            "scripts/smb-print-text.nse",
            45,
            Read,
        ),
        (
            "ip-geolocation-maxmind.maxmind_db",
            "scripts/ip-geolocation-maxmind.nse",
            49,
            Read,
        ),
        (
            "mikrotik-routeros-username-brute.wordlist",
            "scripts/mikrotik-routeros-username-brute.nse",
            86,
            Read,
        ),
        ("oraclesids", "scripts/oracle-sid-brute.nse", 136, Read),
        (
            "puppet-naivesigning.csr",
            "scripts/puppet-naivesigning.nse",
            117,
            Read,
        ),
        (
            "rtsp-url-brute.urlfile",
            "scripts/rtsp-url-brute.nse",
            122,
            Read,
        ),
        (
            "sip-enum-users.userslist",
            "scripts/sip-enum-users.nse",
            229,
            Read,
        ),
        (
            "snmp-brute.communitiesdb",
            "scripts/snmp-brute.nse",
            113,
            Read,
        ),
        (
            "ssh-hostkey.known-hosts",
            "scripts/ssh-hostkey.nse",
            361,
            Read,
        ),
        (
            "publickeydb",
            "scripts/ssh-publickey-acceptance.nse",
            48,
            Read,
        ),
        (
            "ssl-known-key.fingerprintfile",
            "scripts/ssl-known-key.nse",
            113,
            Read,
        ),
        (
            "targets-ipv6-eui64.input",
            "scripts/targets-ipv6-eui64.nse",
            44,
            Read,
        ),
        ("targets-xml.iX", "scripts/targets-xml.nse", 36, Read),
        (
            "bittorrent-discovery.torrent",
            "scripts/bittorrent-discovery.nse",
            51,
            Read,
        ),
        ("ajp-request.filename", "scripts/ajp-request.nse", 52, Write),
        (
            "http-awstatstotals-exec.outfile",
            "scripts/http-awstatstotals-exec.nse",
            97,
            Write,
        ),
        (
            "http-axis2-dir-traversal.outfile",
            "scripts/http-axis2-dir-traversal.nse",
            121,
            Write,
        ),
        (
            "http-majordomo2-dir-traversal.outfile",
            "scripts/http-majordomo2-dir-traversal.nse",
            71,
            Write,
        ),
        (
            "http-phpmyadmin-dir-traversal.outfile",
            "scripts/http-phpmyadmin-dir-traversal.nse",
            100,
            Write,
        ),
        (
            "http-tplink-dir-traversal.outfile",
            "scripts/http-tplink-dir-traversal.nse",
            114,
            Write,
        ),
        ("shodan-api.outfile", "scripts/shodan-api.nse", 80, Write),
        // Appended to.
        ("url-snarf.outfile", "scripts/url-snarf.nse", 86, Write),
        (
            "http-wordpress-users.out",
            "scripts/http-wordpress-users.nse",
            114,
            Write,
        ),
        (
            "supermicro-ipmi-conf.out",
            "scripts/supermicro-ipmi-conf.nse",
            66,
            Write,
        ),
        (
            "ip-geolocation-map-bing.map_path",
            "scripts/ip-geolocation-map-bing.nse",
            156,
            Write,
        ),
        (
            "ip-geolocation-map-google.map_path",
            "scripts/ip-geolocation-map-google.nse",
            138,
            Write,
        ),
        (
            "ip-geolocation-map-kml.map_path",
            "scripts/ip-geolocation-map-kml.nse",
            66,
            Write,
        ),
        (
            "oracle-brute-stealth.johnfile",
            "scripts/oracle-brute-stealth.nse",
            63,
            Write,
        ),
        (
            "traceroute-geolocation.kmlfile",
            "scripts/traceroute-geolocation.nse",
            71,
            Write,
        ),
    ];

    /// Shipped keys that end in a listed short key but open nothing outside
    /// the data directories: `nmap.fetchfile` alone, or `loadfile`, which
    /// scripts do not have here. A read short key may have these readers.
    const OTHER_READERS: &[(&str, &str)] = &[
        (
            "http-default-accounts.fingerprintfile",
            "nmap.fetchfile alone",
        ),
        ("http-enum.fingerprintfile", "nmap.fetchfile alone"),
        ("http-devframework.fingerprintfile", "loadfile"),
        (
            "targets-ipv6-wordlist.wordlist",
            "datafiles: nmap.fetchfile alone",
        ),
        ("tftp-enum.filelist", "datafiles: nmap.fetchfile alone"),
        ("mysql-audit.filename", "loadfile"),
    ];

    /// Keys that name something on the target, or a template: never listed.
    const NEVER: &[&str] = &[
        "file",
        "http-axis2-dir-traversal.file",
        "http-phpmyadmin-dir-traversal.file",
        "http-vuln-cve2006-3392.file",
        "dir",
        "http-phpmyadmin-dir-traversal.dir",
        "http-vlcstreamer-ls.dir",
        "path",
        "url",
        "uri",
        "rfile",
        "basepath",
        "save",
        "stuxnet-detect.save",
        "prefix",
        "hostmap.prefix",
        "ldap.savesearch",
        "ldap.saveprefix",
    ];

    fn tree() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
    }

    fn census_mode(key: &str) -> Option<Opens> {
        CENSUS.iter().find(|c| c.0 == key).map(|c| c.3)
    }

    /// Whether a line of `file` reads `key`: as a string, as a field
    /// (`args.userdb`), or as `SCRIPT_NAME .. ".suffix"` in that script.
    fn line_reads(line: &str, file: &str, key: &str) -> bool {
        let quoted =
            |k: &str| line.contains(&format!("\"{k}\"")) || line.contains(&format!("'{k}'"));
        let field = line.match_indices(&format!(".{key}")).any(|(i, m)| {
            !line[i..][m.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
        });
        let stem = Path::new(file)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let by_name = key
            .strip_prefix(stem)
            .and_then(|r| r.strip_prefix('.'))
            .is_some_and(|suffix| line.contains("SCRIPT_NAME") && quoted(&format!(".{suffix}")));
        quoted(key) || field || by_name
    }

    /// Every key a shipped script or library reads on a line that calls
    /// `get_script_args` or indexes `registry.args`, with `SCRIPT_NAME`
    /// expanded in scripts: `(key, file)`.
    fn reads_in_tree() -> Vec<(String, String)> {
        let mut reads = Vec::new();
        for (dir, ext) in [("scripts", "nse"), ("nselib", "lua")] {
            let mut files: Vec<PathBuf> = std::fs::read_dir(tree().join(dir))
                .expect("the shipped tree")
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == ext))
                .collect();
            files.sort();
            for path in files {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                let name = format!("{dir}/{stem}.{ext}");
                let text =
                    String::from_utf8_lossy(&std::fs::read(&path).expect("read")).into_owned();
                for line in text.lines() {
                    let code = line.split("--").next().unwrap_or("");
                    if !code.contains("get_script_args") && !code.contains("registry.args") {
                        continue;
                    }
                    let mut rest = code;
                    while let Some(i) = rest.find(['"', '\'']) {
                        let q = rest[i..].chars().next().unwrap_or('"');
                        let after = &rest[i..][1..];
                        let Some(j) = after.find(q) else { break };
                        let lit = &after[..j];
                        let key = if dir == "scripts"
                            && lit.starts_with('.')
                            && rest[..i].contains("SCRIPT_NAME")
                        {
                            format!("{stem}{lit}")
                        } else {
                            lit.to_string()
                        };
                        reads.push((key, name.clone()));
                        rest = &after[j..][1..];
                    }
                    for (i, m) in code.match_indices("registry.args.") {
                        let id: String = code[i..][m.len()..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        reads.push((id, name.clone()));
                    }
                }
            }
        }
        reads
    }

    /// Each census row's line reads its key, in the shipped tree.
    #[test]
    #[cfg_attr(miri, ignore = "reads the shipped tree")]
    fn the_census_cites_the_lines_that_read_each_key() {
        for &(key, file, line, _) in CENSUS {
            let text = std::fs::read_to_string(tree().join(file)).expect(file);
            let at = text.lines().nth(line.saturating_sub(1)).unwrap_or("");
            assert!(
                line_reads(at, file, key),
                "{file}:{line} does not read {key}: {at}"
            );
        }
    }

    /// A table lists exactly the census keys of its kind, plus short keys
    /// derived from them: nothing added, dropped or moved between tables.
    #[test]
    #[cfg_attr(miri, ignore = "reads the shipped tree")]
    fn the_tables_are_the_census() {
        use std::collections::BTreeSet;
        for (table, mode) in [
            (&OUTPUT_DIR_ARGS[..], Dir),
            (&READ_FILE_ARGS[..], Read),
            (&WRITE_FILE_ARGS[..], Write),
        ] {
            let listed: BTreeSet<&str> = table
                .iter()
                .copied()
                .filter(|k| k.contains('.') || census_mode(k).is_some())
                .collect();
            let census: BTreeSet<&str> =
                CENSUS.iter().filter(|c| c.3 == mode).map(|c| c.0).collect();
            assert_eq!(listed, census, "{mode:?}");
        }
        for k in NEVER {
            assert!(census_mode(k).is_none(), "{k} is in the census");
            assert!(
                !READ_FILE_ARGS.contains(k)
                    && !WRITE_FILE_ARGS.contains(k)
                    && !OUTPUT_DIR_ARGS.contains(k),
                "{k} is listed"
            );
        }
    }

    /// A short key is listed only where every shipped reader of it, by any
    /// prefix, opens a local file as the table grants: a read short key may
    /// also be written by a reader (`filename`, which ajp-request writes),
    /// or looked up in the data directories alone ([`OTHER_READERS`]).
    #[test]
    #[cfg_attr(miri, ignore = "reads the shipped tree")]
    fn every_reader_of_a_short_key_opens_a_local_file() {
        let reads = reads_in_tree();
        for (table, mode) in [
            (&OUTPUT_DIR_ARGS[..], Dir),
            (&READ_FILE_ARGS[..], Read),
            (&WRITE_FILE_ARGS[..], Write),
        ] {
            for short in table
                .iter()
                .filter(|k| !k.contains('.') && census_mode(k).is_none())
            {
                let suffix = format!(".{short}");
                let readers: Vec<&(String, String)> = reads
                    .iter()
                    .filter(|(k, _)| k == short || k.ends_with(&suffix))
                    .collect();
                assert!(
                    readers.iter().any(|(k, _)| census_mode(k) == Some(mode)),
                    "{short}: no census reader"
                );
                for (k, file) in readers {
                    let ok = match (census_mode(k), mode) {
                        (Some(m), _) if m == mode => true,
                        (Some(Write), Read) => true,
                        (None, Read) => OTHER_READERS.iter().any(|o| o.0 == k),
                        _ => false,
                    };
                    assert!(ok, "{short}: {file} reads {k}, which is not {mode:?}");
                }
            }
        }
    }

    #[test]
    fn prefixes_are_components_not_bytes() {
        let p = policy();
        assert!(!p.allows(Path::new("/usr/share/nmap-evil/x"), false));
        assert!(!p.allows(Path::new("/home/op/loot2/x"), true));
    }
}
