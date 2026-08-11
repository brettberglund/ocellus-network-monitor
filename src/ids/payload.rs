//! Payload signature scanning using an Aho-Corasick automaton compiled from [`SIGNATURES`].

use aho_corasick::AhoCorasick;

use crate::ids::score::{SCORE_PAYLOAD_SIG, Signal};

/// Metadata for a single compiled signature; index-aligned with the Aho-Corasick patterns.
pub struct PayloadRule {
    pub name: &'static str,
    pub score: f32,
}

/// Compiled Aho-Corasick automaton over a mini snort-style ruleset.
pub struct PayloadScanner {
    ac: AhoCorasick,
    rules: Vec<PayloadRule>,
}

impl PayloadScanner {
    pub fn new() -> Self {
        // Each pattern maps 1:1 to a rule by index.
        let (patterns, rules): (Vec<&[u8]>, Vec<PayloadRule>) = SIGNATURES
            .iter()
            .map(|(pat, name, score)| {
                (
                    *pat,
                    PayloadRule {
                        name,
                        score: *score,
                    },
                )
            })
            .unzip();

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("PayloadScanner: failed to compile Aho-Corasick automaton");

        Self { ac, rules }
    }

    /// Scan `payload` and return the first matching signal (highest priority).
    #[allow(dead_code)]
    pub fn scan(&self, payload: &[u8]) -> Option<Signal> {
        let m = self.ac.find(payload)?;
        let rule = &self.rules[m.pattern()];
        Some(Signal {
            name: rule.name,
            score: rule.score,
            detail: format!(
                "Payload signature '{}' matched at offset {}",
                rule.name,
                m.start()
            ),
        })
    }

    /// Scan and return ALL matching signals (deduped by rule name).
    pub fn scan_all(&self, payload: &[u8]) -> Vec<Signal> {
        let mut seen = std::collections::HashSet::new();
        let mut signals = Vec::new();

        for m in self.ac.find_iter(payload) {
            let rule = &self.rules[m.pattern()];
            if seen.insert(rule.name) {
                signals.push(Signal {
                    name: rule.name,
                    score: rule.score,
                    detail: format!(
                        "Payload signature '{}' matched at offset {}",
                        rule.name,
                        m.start()
                    ),
                });
            }
        }
        signals
    }
}

/// (byte_pattern, rule_name, score)
/// Extend this list with additional rulesets (abuse.ch, ET, custom).
static SIGNATURES: &[(&[u8], &str, f32)] = &[
    // Shellcode / exploit indicators
    (
        b"\x90\x90\x90\x90\x90\x90\x90\x90",
        "nop_sled",
        SCORE_PAYLOAD_SIG,
    ),
    (b"\xeb\xfe", "infinite_jmp_loop", SCORE_PAYLOAD_SIG),
    // Metasploit staged payload marker
    (b"MSFV", "metasploit_payload_marker", SCORE_PAYLOAD_SIG),
    // CVE-2021-44228 Log4Shell
    (b"${jndi:", "log4shell_jndi", SCORE_PAYLOAD_SIG),
    // Common webshell keywords
    (
        b"eval(base64_decode",
        "php_webshell_eval_b64",
        SCORE_PAYLOAD_SIG,
    ),
    (b"passthru(", "php_passthru", SCORE_PAYLOAD_SIG),
    (b"cmd.exe /c", "cmd_exec", SCORE_PAYLOAD_SIG),
    (b"/bin/sh -i", "reverse_shell_sh", SCORE_PAYLOAD_SIG),
    // CobaltStrike beacon patterns
    (
        b"Content-Type: application/octet-stream\r\n\r\nMZ",
        "cs_beacon_mz",
        SCORE_PAYLOAD_SIG,
    ),
    // Mimikatz strings
    (
        b"sekurlsa::logonpasswords",
        "mimikatz_sekurlsa",
        SCORE_PAYLOAD_SIG,
    ),
    (b"lsadump::sam", "mimikatz_lsadump", SCORE_PAYLOAD_SIG),
    // SQL injection probes
    (b"' OR '1'='1", "sqli_or_1eq1", 35.0),
    (b"UNION SELECT", "sqli_union_select", 35.0),
    // Directory traversal
    (b"../../etc/passwd", "path_traversal_passwd", 40.0),
    // SSRF probes
    (b"169.254.169.254", "ssrf_aws_metadata", 40.0),
];
