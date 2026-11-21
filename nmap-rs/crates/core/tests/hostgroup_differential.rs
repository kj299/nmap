//! Host-group differential: `core::hostgroup` must form the groups nmap 7.94 forms,
//! in the order it reports them, for every case of `hostgroup_golden.txt`.
//!
//! The golden is nmap's own `-v` output, reduced to group sizes and report order by
//! `tests/differential/m7/gen_hostgroup_golden.py` (M7 cutover gate, step a). Each
//! case names a scan type, a port count, a timing level, the operator's bounds or
//! their absence, and a target list of tokens: `lN` is a loopback address and `own`
//! this host's own, which a raw scan routes over the loopback from another source.
#![cfg(not(miri))]

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use nmap_core::hostgroup::{GroupSizing, HostGroups, Member, RouteKey};

fn golden() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m7/hostgroup_golden.txt");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `l1-l70,own,l1x3` to its tokens, as the generator expands it.
fn expand(list: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in list.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            let (a, b): (u32, u32) = (a[1..].parse().unwrap(), b[1..].parse().unwrap());
            out.extend((a..=b).map(|i| format!("l{i}")));
        } else if let Some((token, n)) = part.rsplit_once('x') {
            let n: usize = n.parse().unwrap();
            out.extend(std::iter::repeat_n(token.to_string(), n));
        } else {
            out.push(part.to_string());
        }
    }
    out
}

const OWN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// A token's address and, for a scan that routes its targets, its route: both kinds
/// go over the loopback, `own` from its own address.
fn member(token: &str, routed: bool) -> Member<String> {
    let (address, source) = if token == "own" {
        (OWN, OWN)
    } else {
        let n: u32 = token[1..].parse().unwrap();
        (Ipv4Addr::from(0x7f00_0000 | n), Ipv4Addr::LOCALHOST)
    };
    Member {
        address: IpAddr::V4(address),
        route: routed.then(|| RouteKey {
            iface: "lo".into(),
            source: IpAddr::V4(source),
            direct: true,
        }),
        item: token.to_string(),
    }
}

#[test]
fn groups_and_order_match_nmap() {
    let text = golden();
    let mut cases = 0;
    for line in text.lines() {
        let mut parts = line.split(" | ");
        let case = parts.next().unwrap();
        let sizes = parts.next().unwrap().strip_prefix("groups=").unwrap();
        let order = parts.next().unwrap().strip_prefix("order=").unwrap();
        let field: HashMap<&str, &str> = case
            .split(' ')
            .map(|kv| kv.split_once('=').unwrap())
            .collect();
        let scan = field["scan"];
        let bound = |k: &str, default: u32| match field[k] {
            "-" => default,
            v => v.parse().unwrap(),
        };
        let sizing = GroupSizing {
            udp: scan.contains('U'),
            tcp: scan.contains(['T', 'S', 'A']),
            tcp_ports: field["ports"].parse().unwrap(),
            timing_level: field["T"].parse().unwrap(),
            min_hostgroup: bound("min", 1),
            max_hostgroup: bound("max", 100_000),
        };
        // As root, 7.94 routes a run's targets unless it is a connect scan under
        // -Pn with neither -O nor --traceroute: `T`. `TO` is -sT -O.
        let routed = scan != "T";
        let targets: Vec<Member<String>> = expand(field["targets"])
            .iter()
            .map(|t| member(t, routed))
            .collect();
        let groups: Vec<Vec<String>> = HostGroups::new(targets.into_iter(), sizing)
            .map(|g| g.into_iter().map(|m| m.item).collect())
            .collect();
        let got_sizes: Vec<String> = groups.iter().map(|g| g.len().to_string()).collect();
        assert_eq!(got_sizes.join(","), sizes, "group sizes: {case}");
        let got_order: Vec<String> = groups.into_iter().flatten().collect();
        assert_eq!(got_order, expand(order), "report order: {case}");
        cases += 1;
    }
    // Pinned so that an emptied or truncated golden cannot pass.
    assert_eq!(cases, 65, "cases in the golden");
}
