//! Installed-program inventory from the four Uninstall roots, with filters and de-duplication.
use crate::env::Env;
use crate::model::*;
use crate::paths::{is_inside, norm};
use crate::registry::{self, read_dword, read_string};
use crate::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use winreg::enums::*;

fn hive_name(h: Hive) -> &'static str {
    match h {
        Hive::Hklm => "HKLM",
        Hive::Hkcu => "HKCU",
    }
}

fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && [9, 14, 19, 24].iter().all(|&i| b[i] == b'-')
        && s[1..37].chars().enumerate().all(|(i, c)| [8, 13, 18, 23].contains(&i) || c.is_ascii_hexdigit())
}

pub fn app_id(src: &RegPath, key_name: &str) -> String {
    let v = if src.view == View::V64 { "64" } else { "32" };
    format!("{}{}:{}", hive_name(src.hive), v, key_name)
}

fn read_app(src: RegPath, key_name: &str, k: &winreg::RegKey) -> Option<InstalledApp> {
    if read_dword(k, "SystemComponent") == Some(1) {
        return None;
    }
    let name = read_string(k, "DisplayName", true)?.trim().to_string();
    if name.is_empty() || read_string(k, "ParentKeyName", false).is_some() {
        return None;
    }
    if let Some(rt) = read_string(k, "ReleaseType", false)
        && ["update", "hotfix", "security update"].contains(&rt.trim().to_lowercase().as_str())
    {
        return None;
    }
    let s = |n: &str| read_string(k, n, false).map(|x| x.trim().to_string()).filter(|x| !x.is_empty());
    Some(InstalledApp {
        id: app_id(&src, key_name),
        key_name: key_name.to_string(),
        per_user: src.hive == Hive::Hkcu,
        sources: vec![src],
        display_name: name,
        display_version: s("DisplayVersion"),
        publisher: s("Publisher"),
        install_location: read_string(k, "InstallLocation", true).map(|x| x.trim().trim_matches('"').to_string()).filter(|x| !x.is_empty()).map(PathBuf::from),
        display_icon: s("DisplayIcon"),
        uninstall_string: s("UninstallString"),
        quiet_uninstall_string: s("QuietUninstallString"),
        modify_path: s("ModifyPath"),
        install_date: s("InstallDate"),
        estimated_size_kb: read_dword(k, "EstimatedSize"),
        windows_installer: read_dword(k, "WindowsInstaller") == Some(1),
        product_code: is_guid(key_name).then(|| key_name.to_string()),
    })
}

pub fn list_apps(env: &Env) -> Result<Vec<InstalledApp>> {
    let mut apps: Vec<InstalledApp> = Vec::new();
    let mut seen: HashMap<(String, String, String, String), usize> = HashMap::new();
    for root in &env.uninstall_roots {
        let Ok(rk) = registry::open(root, KEY_READ) else { continue }; // a missing root is skipped
        let mut names: Vec<String> = rk.enum_keys().flatten().collect();
        names.sort_by_key(|n| n.to_lowercase());
        for name in names {
            let Ok(k) = rk.open_subkey_with_flags(&name, KEY_READ) else { continue };
            let Some(app) = read_app(root.child(&name), &name, &k) else { continue };
            let key = (
                app.display_name.to_lowercase(),
                app.display_version.clone().unwrap_or_default(),
                app.uninstall_string.as_deref().unwrap_or("").trim().to_lowercase(),
                app.install_location.as_deref().map(norm).unwrap_or_default(),
            );
            match seen.get(&key) {
                None => {
                    seen.insert(key, apps.len());
                    apps.push(app);
                }
                Some(&i) => {
                    let src = app.sources[0].clone();
                    // HKCU\Software is shared between the 32- and 64-bit views since Windows 7, so the same
                    // path read through both views is one physical key (Microsoft, "Registry Keys Affected by WOW64").
                    let same_physical = src.hive == Hive::Hkcu
                        && apps[i].sources.iter().any(|x| x.hive == Hive::Hkcu && x.path.eq_ignore_ascii_case(&src.path));
                    if !same_physical {
                        apps[i].sources.push(src);
                    }
                }
            }
        }
    }
    apps.sort_by_key(|a| a.display_name.to_lowercase());
    Ok(apps)
}

pub fn find_app(env: &Env, id: &str) -> Result<InstalledApp> {
    list_apps(env)?.into_iter().find(|a| a.id == id).ok_or_else(|| Error(format!("program not found: {id}")))
}

/// Whether the program's uninstall entry is gone, orphaned (entry kept, program gone) or still present.
pub fn entry_state(app: &InstalledApp, launch: &Launch, exit_code: Option<u32>, windows_dir: &Path) -> EntryState {
    if !app.sources.first().is_some_and(registry::exists) {
        return EntryState::Gone;
    }
    if launch.msi_product.is_some() && exit_code == Some(1605) {
        return EntryState::Orphaned;
    }
    if is_inside(&launch.exe, windows_dir) {
        return EntryState::Present;
    }
    if launch.exe.exists() { EntryState::Present } else { EntryState::Orphaned }
}

/// The DisplayIcon file path: expanded, unquoted, without the trailing `,<index>`.
pub fn icon_path(app: &InstalledApp) -> Option<PathBuf> {
    let raw = registry::expand_env(app.display_icon.as_deref()?.trim());
    let s = raw.trim();
    let s = match s.rsplit_once(',') {
        Some((a, b)) if b.trim().trim_start_matches('-').chars().all(|c| c.is_ascii_digit()) => a,
        _ => s,
    };
    let s = s.trim().trim_matches('"');
    (!s.is_empty()).then(|| PathBuf::from(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_and_icon_path() {
        assert!(is_guid("{8B1E2B3A-0000-4C4C-9999-ABCDEF012345}"));
        assert!(!is_guid("SandboxNotes"));
        let mut a = InstalledApp {
            id: "x".into(), key_name: "x".into(), sources: vec![], display_name: "n".into(), display_version: None, publisher: None,
            install_location: None, display_icon: Some(r#""C:\A B\app.exe",0"#.into()), uninstall_string: None, quiet_uninstall_string: None,
            modify_path: None, install_date: None, estimated_size_kb: None, windows_installer: false, product_code: None, per_user: true,
        };
        assert_eq!(icon_path(&a).unwrap(), PathBuf::from(r"C:\A B\app.exe"));
        a.display_icon = Some(r"C:\a\b.ico".into());
        assert_eq!(icon_path(&a).unwrap(), PathBuf::from(r"C:\a\b.ico"));
    }
}
