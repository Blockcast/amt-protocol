//! Native DRIAD resolver — UDP:53 to system resolver(s).

use std::net::IpAddr;

/// Parse the `nameserver` lines of an /etc/resolv.conf-style string.
/// Returns IPs in declaration order; ignores comments + unknown directives.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut parts = trimmed.split_ascii_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(addr) = parts.next() {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolv_conf_picks_in_order() {
        let txt = "
# comment
search example.
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns.len(), 3);
        assert_eq!(ns[0], "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ns[1], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(ns[2], "2606:4700:4700::1111".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_resolv_conf_skips_comments_and_unknown_directives() {
        let txt = "options edns0\noptions rotate\n; another comment\nnameserver 10.0.0.1\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_resolv_conf_invalid_ip_silently_skipped() {
        let txt = "nameserver not-an-ip\nnameserver 8.8.4.4\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["8.8.4.4".parse::<IpAddr>().unwrap()]);
    }
}
