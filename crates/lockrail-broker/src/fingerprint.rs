//! Command fingerprint for grants (PLAN.md section 3.3, R-11; adv_message_2 M15, adv_message_3 M19).
//!
//! A grant covers one exact command in one exact project state. The fingerprint hashes:
//! - `argv`, `cwd` and the `PATH` the caller passes (`env run` executes with the same one);
//! - sha256 of `argv[0]` as resolved on that `PATH`, of every existing file named in argv, and
//!   of the env file;
//! - a stat fingerprint `(path, size, inode, ctime_ns)` of every file under `cwd`, ignored files
//!   included. `ctime` is used because a user process cannot set it (`touch -d` changes only
//!   atime and mtime), so any write to a file under `cwd` changes the fingerprint.
//!
//! The broker never runs `git` (or any program) against the project: a repository can make
//! `git status` execute programs it names (fsmonitor, filter drivers in `.git/config` and
//! `.gitattributes`). The stat walk already sees every write under `cwd`, including a checkout or
//! an edit to `.git/hooks` and `.git/config`, so nothing is lost by not asking git.
//!
//! Past [`MAX_FILES`] the fingerprint is `Uncapped`: the caller must ask for presence every
//! time. Files outside `cwd` (global installs, `~/.npmrc`, interpreters) are not covered; that is
//! the documented residual.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Stat-walk cap (PLAN.md section 3.3).
pub const MAX_FILES: usize = 200_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fingerprint {
    /// Hex sha256 of everything above.
    Exact(String),
    /// The tree is larger than [`MAX_FILES`]: no grant can be cached for it.
    Uncapped,
}

pub struct Input<'a> {
    pub argv: &'a [String],
    pub cwd: &'a Path,
    /// The caller's `PATH`; `argv[0]` is hashed as resolved on it, so the grant binds the binary
    /// that runs. (The policy's `run_path` is not enforced yet.)
    pub path: &'a str,
    pub env_file: Option<&'a Path>,
}

fn file_hash(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Resolve `argv[0]` on `path` (or as given when it contains a `/`).
pub fn resolve_program(program: &str, cwd: &Path, path: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let p = cwd.join(program);
        return p.is_file().then_some(p);
    }
    path.split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| Path::new(dir).join(program))
        .find(|p| p.is_file())
}

/// Stat every file under `root` (ignored files included). Returns false past the cap.
/// Paths under `cwd` skipped because they churn without changing what a command runs: the
/// reflog, the index and its lock, and fetch bookkeeping. Everything else in `.git` is recorded,
/// refs, `packed-refs`, `HEAD` and objects included, because a commit created with plumbing
/// (`hash-object` + `update-ref`) changes what `git archive HEAD` ships without touching any
/// working-tree file. Matched on the exact path relative to `cwd`.
fn skipped(rel: &Path) -> bool {
    rel == Path::new(".git/logs")
        || rel == Path::new(".git/index")
        || rel == Path::new(".git/index.lock")
        || rel == Path::new(".git/FETCH_HEAD")
        || rel == Path::new(".git/ORIG_HEAD")
}

/// Stat every entry under `root` (ignored files included). Files record (path, size, inode,
/// ctime); directories record (path, inode), so creating or replacing a directory changes the
/// fingerprint without directory ctime churn (a git client creating `index.lock` would otherwise
/// re-prompt every time). Returns false past the cap.
fn stat_walk(root: &Path, h: &mut Sha256) -> Result<bool> {
    let mut stack = vec![root.to_path_buf()];
    let mut entries: Vec<(Vec<u8>, u8, u64, u64, i64, i64)> = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(read) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if skipped(&rel) {
                continue;
            }
            // symlink_metadata: a symlink is recorded as itself (its target may be outside cwd;
            // that residual is documented), and the walk never follows a link out of the tree.
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            let key = rel.as_os_str().as_encoded_bytes().to_vec();
            if meta.is_dir() {
                entries.push((key, b'd', 0, meta.ino(), 0, 0));
                stack.push(path);
            } else {
                entries.push((
                    key,
                    b'f',
                    meta.size(),
                    meta.ino(),
                    meta.ctime(),
                    meta.ctime_nsec(),
                ));
            }
            if entries.len() > MAX_FILES {
                return Ok(false);
            }
        }
    }
    entries.sort_unstable();
    h.update(b"stat2\0");
    for (rel, kind, size, ino, ctime, ctime_ns) in &entries {
        h.update(rel);
        h.update([0, *kind]);
        h.update(size.to_le_bytes());
        h.update(ino.to_le_bytes());
        h.update(ctime.to_le_bytes());
        h.update(ctime_ns.to_le_bytes());
    }
    Ok(true)
}

pub fn compute(input: &Input<'_>) -> Result<Fingerprint> {
    let mut h = Sha256::new();
    h.update(b"lockrail-grant-v1\0");
    for arg in input.argv {
        h.update(arg.as_bytes());
        h.update(b"\0");
    }
    let cwd = input.cwd.canonicalize().context("cwd")?;
    h.update(cwd.as_os_str().as_encoded_bytes());
    h.update(b"\0");
    h.update(input.path.as_bytes());
    h.update(b"\0");
    if let Some(program) = input.argv.first()
        && let Some(resolved) = resolve_program(program, &cwd, input.path)
    {
        h.update(file_hash(&resolved).unwrap_or_default().as_bytes());
    }
    for arg in input.argv.iter().skip(1) {
        let candidate = cwd.join(arg);
        if candidate.is_file()
            && let Some(hash) = file_hash(&candidate)
        {
            h.update(arg.as_bytes());
            h.update(hash.as_bytes());
        }
    }
    if let Some(env_file) = input.env_file {
        h.update(file_hash(env_file).unwrap_or_default().as_bytes());
    }
    if !stat_walk(&cwd, &mut h)? {
        return Ok(Fingerprint::Uncapped);
    }
    Ok(Fingerprint::Exact(hex::encode(h.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn fp(dir: &Path, argv: &[&str]) -> Fingerprint {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        compute(&Input {
            argv: &argv,
            cwd: dir,
            path: "/usr/bin:/bin",
            env_file: None,
        })
        .unwrap()
    }

    fn sh(dir: &Path, script: &str) {
        let ok = Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(dir)
            .status()
            .unwrap()
            .success();
        assert!(ok, "{script}");
    }

    #[test]
    fn edits_to_unnamed_tracked_and_ignored_files_change_the_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        sh(
            d,
            "git init -q && mkdir -p scripts node_modules/some-dep \
                && echo 'console.log(1)' > scripts/deploy.js \
                && echo 'module.exports=1' > node_modules/some-dep/index.js \
                && echo node_modules > .gitignore && git add -A",
        );
        let base = fp(d, &["npm", "run", "deploy"]);
        assert!(matches!(base, Fingerprint::Exact(_)));
        assert_eq!(base, fp(d, &["npm", "run", "deploy"]), "not deterministic");

        // Tracked file not named in argv.
        sh(d, "echo 'console.log(2)' > scripts/deploy.js");
        let after_tracked = fp(d, &["npm", "run", "deploy"]);
        assert_ne!(base, after_tracked, "tracked edit kept the grant");

        // Gitignored file, edited and then mtime restored: ctime still moves.
        sh(
            d,
            "touch -r node_modules/some-dep/index.js /tmp/.lockrail-ref-$$ \
                && echo 'module.exports=require(\"child_process\")' > node_modules/some-dep/index.js \
                && touch -r /tmp/.lockrail-ref-$$ node_modules/some-dep/index.js; rm -f /tmp/.lockrail-ref-$$",
        );
        assert_ne!(
            after_tracked,
            fp(d, &["npm", "run", "deploy"]),
            "ignored edit kept the grant"
        );
    }

    #[test]
    fn non_git_directory_is_covered_by_the_stat_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::write(d.join("run.sh"), "echo hi").unwrap();
        let base = fp(d, &["sh", "run.sh"]);
        std::thread::sleep(std::time::Duration::from_millis(5));
        fs::write(d.join("helper.sh"), "curl evil").unwrap();
        assert_ne!(base, fp(d, &["sh", "run.sh"]));
    }

    #[test]
    fn argv_and_cwd_are_part_of_the_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let a = fp(tmp.path(), &["npm", "run", "deploy"]);
        let b = fp(tmp.path(), &["npm", "run", "deploy", "--force"]);
        assert_ne!(a, b);
    }

    #[test]
    fn new_directories_and_nested_names_are_covered() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::create_dir_all(d.join("src/refs")).unwrap();
        fs::write(d.join("src/refs/x.js"), "1").unwrap();
        let base = fp(d, &["npm", "run", "deploy"]);
        // A directory named like a git internal, outside `.git`, is not skipped.
        fs::write(d.join("src/refs/x.js"), "2").unwrap();
        let edited = fp(d, &["npm", "run", "deploy"]);
        assert_ne!(base, edited, "an edit under src/refs kept the grant");
        // An empty new directory changes the fingerprint.
        fs::create_dir(d.join("plugins")).unwrap();
        assert_ne!(
            edited,
            fp(d, &["npm", "run", "deploy"]),
            "a new directory kept the grant"
        );
    }

    /// Writes `.git/hooks` and `.git/config` in a throwaway repo. Ignored until the owner rules on
    /// config-writing fixtures (the git-guard rule: agents never set git config).
    #[test]
    #[ignore]
    fn git_hooks_and_config_changes_invalidate_the_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        sh(d, "git init -q && echo x > a && git add a");
        let base = fp(d, &["npm", "run", "deploy"]);
        assert_eq!(
            base,
            fp(d, &["npm", "run", "deploy"]),
            "git status must not churn the fingerprint"
        );
        sh(
            d,
            "printf '#!/bin/sh\\ncurl evil\\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push",
        );
        let after_hook = fp(d, &["npm", "run", "deploy"]);
        assert_ne!(base, after_hook, "a new git hook kept the grant");
        sh(
            d,
            "printf '[core]\\n\\thooksPath = /tmp/x\\n' >> .git/config",
        );
        assert_ne!(
            after_hook,
            fp(d, &["npm", "run", "deploy"]),
            "a config change kept the grant"
        );
    }

    /// GATE 4: fingerprint time with 100000 files under `node_modules`, p95 < 300 ms (release).
    /// Run by hand: `cargo test --release -p lockrail-broker -- --ignored fingerprint_100k`.
    #[test]
    #[ignore]
    fn fingerprint_100k_files_p95_under_300ms() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for pkg in 0..1000 {
            let dir = d.join("node_modules").join(format!("pkg{pkg}"));
            fs::create_dir_all(&dir).unwrap();
            for f in 0..100 {
                fs::write(dir.join(format!("f{f}.js")), b"x").unwrap();
            }
        }
        let mut times: Vec<std::time::Duration> = (0..20)
            .map(|_| {
                let t = std::time::Instant::now();
                assert!(matches!(
                    fp(d, &["npm", "run", "deploy"]),
                    Fingerprint::Exact(_)
                ));
                t.elapsed()
            })
            .collect();
        times.sort();
        let p95 = times[18];
        eprintln!(
            "fingerprint 100k files: min {:?} p50 {:?} p95 {:?}",
            times[0], times[10], p95
        );
        assert!(p95 < std::time::Duration::from_millis(300), "p95 {p95:?}");
    }
}
