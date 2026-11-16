#![allow(dead_code)]
//! Test fixture: a sandbox seeded under a temp dir with a unique registry tag. Drop cleans both.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::TempDir;
use uni_core::env::Env;
use uni_core::paths::file_id;
use uni_core::sandbox;

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct Fixture {
    pub root: PathBuf,
    pub tag: String,
    pub env: Env,
    _dir: TempDir,
    second: TempDir,
    _data: Option<TempDir>,
}

fn tag() -> String {
    format!("t{}_{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst))
}

impl Fixture {
    pub fn new() -> Fixture {
        Self::seeded(tempfile::tempdir().unwrap(), None)
    }

    fn seeded(dir: TempDir, data: Option<TempDir>) -> Fixture {
        let tag = tag();
        let mut env = sandbox::seed(dir.path(), &tag).unwrap();
        if let Some(d) = &data {
            env.data_dir = uni_core::paths::canonical(d.path()).unwrap();
        }
        let root = env.data_dir.parent().unwrap().to_path_buf();
        let root = if data.is_some() { uni_core::paths::canonical(dir.path()).unwrap() } else { root };
        Fixture { root, tag, env, _dir: dir, second: tempfile::tempdir().unwrap(), _data: data }
    }

    /// An extra temp dir for "outside" targets, owned by the fixture.
    pub fn second_dir(&self) -> &Path {
        self.second.path()
    }

    /// Fixture under the target tmp dir with `data_dir` in %TEMP%. None when both are on the same volume.
    pub fn other_volume() -> Option<Fixture> {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let data = tempfile::tempdir().unwrap();
        if file_id(dir.path()).unwrap().volume == file_id(data.path()).unwrap().volume {
            return None;
        }
        Some(Self::seeded(dir, Some(data)))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = sandbox::clean(&self.root, &self.tag);
    }
}
