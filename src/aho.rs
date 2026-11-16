//! Aho-Corasick multi-pattern prefilter with dense 256-way transitions.
//!
//! Two automata are maintained by the scanner: one over exact bytes and one
//! over ASCII-lowercased bytes (for nocase patterns). Every output records the
//! atom length so a hit yields its exact start offset.

#[derive(Debug, Clone)]
pub struct AcHit {
    pub pattern: usize,
    pub start: usize,
    #[allow(dead_code)]
    pub end: usize,
}

struct Node {
    next: [u32; 256],
    fail: u32,
    /// (pattern id, atom length) for patterns ending at this node
    outputs: Vec<(usize, usize)>,
}

pub struct AhoCorasick {
    nodes: Vec<Node>,
}

impl AhoCorasick {
    pub fn new() -> Self {
        AhoCorasick {
            nodes: vec![Node { next: [0; 256], fail: 0, outputs: Vec::new() }],
        }
    }

    pub fn insert(&mut self, atom: &[u8], pattern: usize) {
        let mut cur = 0u32;
        for &c in atom {
            let nxt = self.nodes[cur as usize].next[c as usize];
            if nxt == 0 {
                let id = self.nodes.len() as u32;
                self.nodes.push(Node { next: [0; 256], fail: 0, outputs: Vec::new() });
                self.nodes[cur as usize].next[c as usize] = id;
                cur = id;
            } else {
                cur = nxt;
            }
        }
        self.nodes[cur as usize].outputs.push((pattern, atom.len()));
    }

    /// Build failure links and complete the goto table (automaton form: one
    /// table lookup per input byte during scanning).
    pub fn build(&mut self) {
        let mut queue = std::collections::VecDeque::new();
        for c in 0..256usize {
            let nxt = self.nodes[0].next[c];
            if nxt != 0 {
                self.nodes[nxt as usize].fail = 0;
                queue.push_back(nxt);
            }
        }
        while let Some(u) = queue.pop_front() {
            for c in 0..256usize {
                let v = self.nodes[u as usize].next[c];
                if v != 0 {
                    let mut f = self.nodes[u as usize].fail;
                    while f != 0 && self.nodes[f as usize].next[c] == 0 {
                        f = self.nodes[f as usize].fail;
                    }
                    let fv = self.nodes[f as usize].next[c];
                    self.nodes[v as usize].fail = if fv == v { 0 } else { fv };
                    let fail_outputs = self.nodes[fv as usize].outputs.clone();
                    self.nodes[v as usize].outputs.extend(fail_outputs);
                    queue.push_back(v);
                } else {
                    let f = self.nodes[u as usize].fail;
                    self.nodes[u as usize].next[c] = self.nodes[f as usize].next[c];
                }
            }
        }
    }

    /// Scan `data`. When `fold` is true every input byte is lowercased first,
    /// matching atoms inserted in lowercase. Emits every hit including
    /// overlapping matches and failure-link outputs.
    pub fn scan<F: FnMut(AcHit)>(&self, data: &[u8], fold: bool, mut f: F) {
        let mut state = 0u32;
        for (i, &b) in data.iter().enumerate() {
            let c = if fold { b.to_ascii_lowercase() } else { b };
            state = self.nodes[state as usize].next[c as usize];
            let outs = &self.nodes[state as usize].outputs;
            for &(pid, len) in outs {
                f(AcHit { pattern: pid, start: i + 1 - len, end: i + 1 });
            }
        }
    }

    #[allow(dead_code)]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(ac: &AhoCorasick, data: &[u8], fold: bool) -> Vec<(usize, usize, usize)> {
        let mut hits = Vec::new();
        ac.scan(data, fold, |h| hits.push((h.pattern, h.start, h.end)));
        hits.sort();
        hits
    }

    #[test]
    fn multi_pattern_overlapping() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"he", 0);
        ac.insert(b"she", 1);
        ac.insert(b"his", 2);
        ac.build();
        // "shes": she@0..3 and he@1..3
        let hits = collect(&ac, b"shes", false);
        assert!(hits.contains(&(1, 0, 3)));
        assert!(hits.contains(&(0, 1, 3)));
    }

    #[test]
    fn fold_scan_matches_case_insensitive() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"abc", 0);
        ac.build();
        let hits = collect(&ac, b"AbC", true);
        assert_eq!(hits, vec![(0, 0, 3)]);
    }

    #[test]
    fn repeated_occurrences() {
        let mut ac = AhoCorasick::new();
        ac.insert(b"aa", 0);
        ac.build();
        let hits = collect(&ac, b"aaaa", false);
        // three overlapping occurrences at offsets 0, 1, 2
        assert_eq!(hits, vec![(0, 0, 2), (0, 1, 3), (0, 2, 4)]);
    }
}
