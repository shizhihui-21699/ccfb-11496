//! Aho-Corasick automata used as the multi-pattern prefilter.
//!
//! Two automata are maintained:
//! - an exact (case-sensitive) automaton fed the raw bytes;
//! - a case-insensitive automaton whose patterns and input are ASCII-lowercased.
//!
//! Each pattern carries `(rule_idx, string_idx)` owners. A single linear pass
//! over the file walks both automata and yields every atom hit; only candidate
//! strings are then verified precisely.

const ALPHA: usize = 256;

struct Node {
    next: [u32; ALPHA],
    fail: u32,
    /// pattern ids ending exactly at this node
    out: Vec<u32>,
    /// nearest failure ancestor that itself has an output (u32::MAX if none)
    dict: u32,
}

impl Default for Node {
    fn default() -> Self {
        Self { next: [u32::MAX; ALPHA], fail: 0, out: Vec::new(), dict: u32::MAX }
    }
}

struct Automaton {
    nodes: Vec<Node>,
    patterns: Vec<Vec<u8>>,
    /// pattern id -> owners (rule index, string index, wide-view?)
    owners: Vec<Vec<(usize, usize, bool)>>,
}

impl Automaton {
    fn new() -> Self {
        let mut root = Node::default();
        root.next.fill(u32::MAX);
        root.dict = u32::MAX;
        Self { nodes: vec![root], patterns: Vec::new(), owners: Vec::new() }
    }

    fn insert(&mut self, atom: &[u8], owner: (usize, usize, bool)) -> u32 {
        if let Some(id) = self.patterns.iter().position(|p| p.as_slice() == atom) {
            let o = &mut self.owners[id];
            if !o.contains(&owner) {
                o.push(owner);
            }
            return id as u32;
        }
        let id = self.patterns.len() as u32;
        let mut cur = 0u32;
        for &b in atom {
            let c = b as usize;
            let nxt = self.nodes[cur as usize].next[c];
            if nxt == u32::MAX {
                let nn = self.nodes.len() as u32;
                let mut node = Node::default();
                node.next.fill(u32::MAX);
                node.dict = u32::MAX;
                self.nodes.push(node);
                self.nodes[cur as usize].next[c] = nn;
                cur = nn;
            } else {
                cur = nxt;
            }
        }
        self.nodes[cur as usize].out.push(id);
        self.patterns.push(atom.to_vec());
        self.owners.push(vec![owner]);
        id
    }

    fn build(&mut self) {
        let mut queue = std::collections::VecDeque::new();
        for c in 0..ALPHA {
            let n = self.nodes[0].next[c];
            if n == u32::MAX {
                self.nodes[0].next[c] = 0;
            } else {
                self.nodes[n as usize].fail = 0;
                queue.push_back(n);
            }
        }
        while let Some(u) = queue.pop_front() {
            for c in 0..ALPHA {
                let v = self.nodes[u as usize].next[c];
                if v == u32::MAX {
                    let f = self.nodes[u as usize].fail;
                    self.nodes[u as usize].next[c] = self.nodes[f as usize].next[c];
                } else {
                    let f = self.nodes[u as usize].fail;
                    self.nodes[v as usize].fail = self.nodes[f as usize].next[c];
                    queue.push_back(v);
                }
            }
            let f = self.nodes[u as usize].fail;
            self.nodes[u as usize].dict = if !self.nodes[f as usize].out.is_empty() {
                f
            } else {
                self.nodes[f as usize].dict
            };
        }
    }

    fn emit<F: FnMut(usize, usize, bool, usize, usize)>(
        &self,
        state: u32,
        pos: usize,
        on_hit: &mut F,
    ) {
        let s = state;
        for &pid in &self.nodes[s as usize].out {
            let len = self.patterns[pid as usize].len();
            for &(r, si, wide) in &self.owners[pid as usize] {
                on_hit(r, si, wide, pos + 1 - len, len);
            }
        }
        let mut d = self.nodes[s as usize].dict;
        while d != u32::MAX {
            for &pid in &self.nodes[d as usize].out {
                let len = self.patterns[pid as usize].len();
                for &(r, si, wide) in &self.owners[pid as usize] {
                    on_hit(r, si, wide, pos + 1 - len, len);
                }
            }
            d = self.nodes[d as usize].dict;
        }
    }
}

pub struct Aho {
    exact: Automaton,
    nocase: Automaton,
    /// atoms expanded to UTF-16LE form (byte, 0x00, byte, 0x00, ...)
    wide_exact: Automaton,
    wide_nocase: Automaton,
}

impl Aho {
    pub fn new() -> Self {
        Self {
            exact: Automaton::new(),
            nocase: Automaton::new(),
            wide_exact: Automaton::new(),
            wide_nocase: Automaton::new(),
        }
    }

    /// Add an atom owned by `(rule_idx, string_idx)`.
    /// `wide` controls whether wide-expanded copies are registered.
    pub fn add_atom(&mut self, raw_atom: &[u8], nocase: bool, wide: bool, owner: (usize, usize)) {
        if wide {
            let expanded: Vec<u8> = raw_atom
                .iter()
                .flat_map(|b| if nocase { vec![b.to_ascii_lowercase(), 0] } else { vec![*b, 0] })
                .collect();
            if nocase {
                self.wide_nocase.insert(&expanded, (owner.0, owner.1, true));
            } else {
                self.wide_exact.insert(&expanded, (owner.0, owner.1, true));
            }
        }
        if nocase {
            let lower: Vec<u8> = raw_atom.iter().map(|b| b.to_ascii_lowercase()).collect();
            self.nocase.insert(&lower, (owner.0, owner.1, false));
        } else {
            self.exact.insert(raw_atom, (owner.0, owner.1, false));
        }
    }

    pub fn build(&mut self) {
        self.exact.build();
        self.nocase.build();
        self.wide_exact.build();
        self.wide_nocase.build();
    }

    /// Scan `data`; callback receives
    /// (rule_idx, string_idx, wide_view, offset, physical_atom_len).
    pub fn scan<F: FnMut(usize, usize, bool, usize, usize)>(
        &self,
        data: &[u8],
        mut on_hit: F,
    ) {
        let mut se = 0u32;
        let mut sn = 0u32;
        let mut swe = 0u32;
        let mut swn = 0u32;
        for (i, &b) in data.iter().enumerate() {
            se = self.exact.nodes[se as usize].next[b as usize];
            self.exact.emit(se, i, &mut on_hit);

            let lc = b.to_ascii_lowercase();
            sn = self.nocase.nodes[sn as usize].next[lc as usize];
            self.nocase.emit(sn, i, &mut on_hit);

            swe = self.wide_exact.nodes[swe as usize].next[b as usize];
            self.wide_exact.emit(swe, i, &mut on_hit);

            swn = self.wide_nocase.nodes[swn as usize].next[lc as usize];
            self.wide_nocase.emit(swn, i, &mut on_hit);
        }
    }
}
