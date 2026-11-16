//! Operations: describe, preview, uninstall flow, apply, restore, history.
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::{find_app, list_apps};
use crate::model::*;
use crate::paths::norm;
use crate::{Error, Result, now_ms};
use std::fs;
use std::path::PathBuf;

pub fn describe(env: &Env, app_id: &str) -> Result<AppDetails> {
    let app = find_app(env, app_id)?;
    let (launch, launch_error) = match app.uninstall_string.as_deref() {
        None => (None, Some("no uninstall command".to_string())),
        Some(raw) => match parse_uninstall(raw, &env.folders.system_dir, app.product_code.as_deref()) {
            Ok(l) => (Some(l), None),
            Err(e) => (None, Some(e)),
        },
    };
    Ok(AppDetails { app, launch, launch_error })
}

/// Every other listed program: the app itself (same id or an intersecting source) is removed.
fn others(env: &Env, app: &InstalledApp) -> Result<Vec<InstalledApp>> {
    Ok(list_apps(env)?.into_iter().filter(|a| a.id != app.id && !a.sources.iter().any(|s| app.sources.iter().any(|x| x.same(s)))).collect())
}

/// Dry run, read-only.
pub fn preview(env: &Env, app_id: &str) -> Result<Plan> {
    let d = describe(env, app_id)?;
    let others = others(env, &d.app)?;
    crate::scan::scan(env, &d.app, d.launch.as_ref(), &others, true)
}

/// Stable id of a target; the same across rescans.
pub fn target_key(t: &Target) -> String {
    let rp = |k: &RegPath| {
        let h = if k.hive == Hive::Hklm { "hklm" } else { "hkcu" };
        let v = if k.view == View::V64 { "64" } else { "32" };
        format!("{h}{v}:{}", k.path.to_lowercase())
    };
    match t {
        Target::Path { path, .. } => format!("path:{}", norm(path)),
        Target::RegKey { key } => format!("key:{}", rp(key)),
        Target::RegValue { key, name } => format!("value:{}|{}", rp(key), name.to_lowercase()),
    }
}

pub fn safe_file_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' }).take(80).collect()
}

fn strip_payloads(i: &Ident) -> Ident {
    match i {
        Ident::Key { .. } | Ident::Value { .. } => Ident::None {},
        other => other.clone(),
    }
}

fn write_json(path: &PathBuf, value: &impl serde::Serialize) -> Result<()> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

/// `data_dir\plans\<app>-<ms>.json`, registry payloads stripped.
pub fn export_plan(env: &Env, plan: &Plan) -> Result<PathBuf> {
    let mut p = plan.clone();
    for c in &mut p.candidates {
        c.ident = strip_payloads(&c.ident);
    }
    let path = env.data_dir.join("plans").join(format!("{}-{}.json", safe_file_name(&plan.app_id), now_ms()));
    write_json(&path, &p).map_err(|e| Error(format!("cannot write the plan: {e}")))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_key_is_stable() {
        let k = RegPath::new(Hive::Hkcu, View::V32, r"Software\Foo\Bar");
        let k2 = RegPath::new(Hive::Hkcu, View::V32, r"SOFTWARE\foo\BAR");
        assert_eq!(target_key(&Target::RegKey { key: k.clone() }), target_key(&Target::RegKey { key: k2.clone() }));
        assert_eq!(target_key(&Target::RegKey { key: k.clone() }), r"key:hkcu32:software\foo\bar");
        assert_eq!(target_key(&Target::RegValue { key: k, name: "Run".into() }), r"value:hkcu32:software\foo\bar|run");
        let p = |s: &str| Target::Path { path: PathBuf::from(s), kind: PathKind::File };
        assert_eq!(target_key(&p(r"C:\A\B\")), target_key(&p("c:/a/b")));
        assert_eq!(target_key(&p(r"C:\A\B")), r"path:c:\a\b");
    }

    #[test]
    fn export_names_are_sanitized() {
        assert_eq!(safe_file_name("HKLM64:{AB}*?"), "HKLM64__AB___");
        assert_eq!(safe_file_name(&"x".repeat(200)).len(), 80);
        assert_eq!(safe_file_name(r"..\evil/name"), ".._evil_name");
    }
}
