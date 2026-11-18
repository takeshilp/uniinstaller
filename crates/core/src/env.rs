//! The environment every operation runs against: folders, registry roots, data dir.
//! Real system or a sandbox; destructive code never reads real locations except through `Env`.
use crate::model::{Hive, RegPath, View};
use crate::paths::{canonical, is_local_abs};
use crate::{Error, Result};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::*;
use windows::core::GUID;

pub const SANDBOX_MARKER: &str = ".uniinstaller-sandbox";
pub const SANDBOX_VAR: &str = "UNIINSTALLER_SANDBOX";
pub const TEST_KEY_PREFIX: &str = r"Software\uniinstaller-tests";
/// The Tauri identifier (`src-tauri/tauri.conf.json`, kept equal by a test there): the GUI's WebView2 profile lives in
/// `%LOCALAPPDATA%\<identifier>`, so it is a protected tree and never traced.
pub const APP_IDENTIFIER: &str = "io.github.takeshilp.uniinstaller";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const RUN: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const APP_PATHS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

#[derive(Clone, Debug, Default)]
pub struct Folders {
    /// Zones where file leftovers may be proposed.
    pub program_files: Vec<PathBuf>,
    pub app_data: Vec<PathBuf>,
    pub start_menu: Vec<PathBuf>,
    pub desktops: Vec<PathBuf>,
    /// Blocked if equal to or an ancestor of the candidate's path (inside is allowed).
    pub protected_roots: Vec<PathBuf>,
    /// Blocked if equal, ancestor or inside.
    pub protected_trees: Vec<PathBuf>,
    pub windows_dir: PathBuf,
    /// Used to resolve bare exe names; real even in the sandbox.
    pub system_dir: PathBuf,
}

impl Folders {
    pub fn zone_roots(&self) -> impl Iterator<Item = &PathBuf> {
        self.program_files.iter().chain(&self.app_data).chain(&self.start_menu).chain(&self.desktops)
    }

    /// Builds the classified folder set from named folders. Folders that exist are canonicalized.
    pub fn build(named: &HashMap<&'static str, PathBuf>, data_dir: &Path) -> Result<Folders> {
        for req in ["Windows", "System", "ProgramFiles", "ProgramData", "Profile", "RoamingAppData", "LocalAppData"] {
            if !named.contains_key(req) {
                return Err(Error(format!("known folder {req} could not be resolved")));
            }
        }
        let n: HashMap<&str, PathBuf> =
            named.iter().map(|(k, v)| (*k, if v.exists() { canonical(v).unwrap_or_else(|_| v.clone()) } else { v.clone() })).collect();
        let get = |k: &str| n.get(k).cloned();
        let list = |ks: &[&str]| -> Vec<PathBuf> { ks.iter().filter_map(|k| get(k)).collect() };
        let program_files = list(&["ProgramFiles", "ProgramFilesX86", "UserProgramFiles"]);
        let app_data = list(&["RoamingAppData", "LocalAppData", "LocalAppDataLow", "ProgramData"]);
        let start_menu = list(&["Programs", "CommonPrograms"]);
        let desktops = list(&["Desktop", "PublicDesktop"]);

        let mut roots = list(&[
            "UserProfiles", "Profile", "Public", "ProgramFiles", "ProgramFilesX86", "ProgramData", "RoamingAppData", "LocalAppData",
            "LocalAppDataLow", "UserProgramFiles", "Programs", "CommonPrograms", "StartMenu", "CommonStartMenu", "Startup", "CommonStartup",
        ]);
        if let Some(up) = get("UserProfiles")
            && let Ok(rd) = std::fs::read_dir(&up)
        {
            roots.extend(rd.flatten().filter(|e| e.path().is_dir()).map(|e| e.path()));
        }
        if let Ok(t) = canonical(&std::env::temp_dir()) {
            roots.push(t);
        }
        for z in program_files.iter().chain(&app_data).chain(&start_menu).chain(&desktops) {
            roots.push(z.clone());
        }

        let mut trees = list(&[
            "Windows", "ProgramFilesCommon", "ProgramFilesCommonX86", "Documents", "Pictures", "Videos", "Music", "Downloads", "SavedGames",
            "Desktop", "PublicDesktop", "PublicDocuments", "PublicDownloads", "PublicMusic", "PublicPictures", "PublicVideos", "SkyDrive",
        ]);
        let sub = |k: &str, s: &str| get(k).map(|p| p.join(s));
        trees.extend([
            sub("ProgramFiles", "WindowsApps"),
            sub("ProgramData", "Microsoft"),
            sub("ProgramData", "Package Cache"),
            sub("RoamingAppData", "Microsoft"),
            sub("LocalAppData", "Microsoft"),
            sub("LocalAppData", "Packages"),
            // the GUI's WebView2 profile (Tauri identifier)
            sub("LocalAppData", APP_IDENTIFIER),
            sub("RoamingAppData", APP_IDENTIFIER),
        ]
        .into_iter()
        .flatten());
        trees.push(data_dir.to_path_buf());
        if let Some(d) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
            trees.push(canonical(&d).unwrap_or(d));
        }
        Ok(Folders {
            program_files,
            app_data,
            start_menu,
            desktops,
            protected_roots: roots,
            protected_trees: trees,
            windows_dir: n["Windows"].clone(),
            system_dir: n["System"].clone(),
        })
    }

    /// The real machine's folders (Known Folders API, never hardcoded drive letters).
    pub fn system(data_dir: &Path) -> Result<Folders> {
        let ids: &[(&'static str, &GUID)] = &[
            ("Windows", &FOLDERID_Windows),
            ("System", &FOLDERID_System),
            ("ProgramFiles", &FOLDERID_ProgramFiles),
            ("ProgramFilesX86", &FOLDERID_ProgramFilesX86),
            ("ProgramFilesCommon", &FOLDERID_ProgramFilesCommon),
            ("ProgramFilesCommonX86", &FOLDERID_ProgramFilesCommonX86),
            ("ProgramData", &FOLDERID_ProgramData),
            ("UserProfiles", &FOLDERID_UserProfiles),
            ("Profile", &FOLDERID_Profile),
            ("Public", &FOLDERID_Public),
            ("RoamingAppData", &FOLDERID_RoamingAppData),
            ("LocalAppData", &FOLDERID_LocalAppData),
            ("LocalAppDataLow", &FOLDERID_LocalAppDataLow),
            ("UserProgramFiles", &FOLDERID_UserProgramFiles),
            ("Programs", &FOLDERID_Programs),
            ("CommonPrograms", &FOLDERID_CommonPrograms),
            ("StartMenu", &FOLDERID_StartMenu),
            ("CommonStartMenu", &FOLDERID_CommonStartMenu),
            ("Startup", &FOLDERID_Startup),
            ("CommonStartup", &FOLDERID_CommonStartup),
            ("Desktop", &FOLDERID_Desktop),
            ("PublicDesktop", &FOLDERID_PublicDesktop),
            ("Documents", &FOLDERID_Documents),
            ("Pictures", &FOLDERID_Pictures),
            ("Videos", &FOLDERID_Videos),
            ("Music", &FOLDERID_Music),
            ("Downloads", &FOLDERID_Downloads),
            ("SavedGames", &FOLDERID_SavedGames),
            ("PublicDocuments", &FOLDERID_PublicDocuments),
            ("PublicDownloads", &FOLDERID_PublicDownloads),
            ("PublicMusic", &FOLDERID_PublicMusic),
            ("PublicPictures", &FOLDERID_PublicPictures),
            ("PublicVideos", &FOLDERID_PublicVideos),
            ("SkyDrive", &FOLDERID_SkyDrive),
        ];
        let mut named = HashMap::new();
        for (name, id) in ids {
            // A folder that fails (for example UserProgramFiles is absent) is skipped.
            // SAFETY: the returned PWSTR is freed with CoTaskMemFree right after copying.
            unsafe {
                if let Ok(p) = SHGetKnownFolderPath(*id, KF_FLAG_DEFAULT, None) {
                    let s = p.to_string();
                    CoTaskMemFree(Some(p.0 as *const _));
                    if let Ok(s) = s {
                        named.insert(*name, PathBuf::from(s));
                    }
                }
            }
        }
        Folders::build(&named, data_dir)
    }
}

#[derive(Clone, Debug)]
pub struct Env {
    pub folders: Folders,
    /// Preference order: HKLM64, HKLM32, HKCU64, HKCU32.
    pub uninstall_roots: Vec<RegPath>,
    pub run_roots: Vec<RegPath>,
    pub app_paths_roots: Vec<RegPath>,
    pub software_roots: Vec<RegPath>,
    pub data_dir: PathBuf,
    pub sandbox: bool,
}

impl Env {
    // shortcut: elevating with a different admin account changes %LOCALAPPDATA%, so history looks empty there; fixed by the stage-2 helper.
    pub fn system() -> Result<Env> {
        // shortcut: only the current user's HKCU and profile are scanned, add other users' hives in stage 2.
        let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or_else(|| Error("LOCALAPPDATA is not set".into()))?;
        let data_dir = local.join("uniinstaller-data");
        let both = |hives: &[(Hive, View)], p: &str| hives.iter().map(|(h, v)| RegPath::new(*h, *v, p)).collect::<Vec<_>>();
        use Hive::*;
        use View::*;
        Ok(Env {
            folders: Folders::system(&data_dir)?,
            uninstall_roots: both(&[(Hklm, V64), (Hklm, V32), (Hkcu, V64), (Hkcu, V32)], UNINSTALL),
            run_roots: both(&[(Hkcu, V64), (Hklm, V64), (Hklm, V32)], RUN),
            app_paths_roots: both(&[(Hklm, V64), (Hklm, V32), (Hkcu, V64)], APP_PATHS),
            software_roots: vec![RegPath::new(Hkcu, V64, "Software"), RegPath::new(Hklm, V64, "SOFTWARE"), RegPath::new(Hklm, V32, "SOFTWARE")],
            data_dir,
            sandbox: false,
        })
    }

    /// Folders under `root`, registry under `HKCU\Software\uniinstaller-tests\<tag>`.
    pub fn sandbox(root: &Path, tag: &str) -> Env {
        assert!(valid_tag(tag), "invalid sandbox tag");
        // The root may be an 8.3 path such as C:\Users\LONGNA~1\...
        let root = canonical(root).unwrap_or_else(|_| root.to_path_buf());
        let r = |p: &str| root.join(p);
        let sm = r(r"users\me\AppData\Roaming\Microsoft\Windows\Start Menu");
        let csm = r(r"pd\Microsoft\Windows\Start Menu");
        let real = real_win_dirs();
        let named: HashMap<&'static str, PathBuf> = HashMap::from([
            ("Windows", real.0),
            ("System", real.1),
            ("ProgramFiles", r("pf")),
            ("ProgramFilesX86", r("pfx86")),
            ("ProgramFilesCommon", r(r"pf\Common Files")),
            ("ProgramFilesCommonX86", r(r"pfx86\Common Files")),
            ("ProgramData", r("pd")),
            ("UserProfiles", r("users")),
            ("Profile", r(r"users\me")),
            ("Public", r(r"users\Public")),
            ("RoamingAppData", r(r"users\me\AppData\Roaming")),
            ("LocalAppData", r(r"users\me\AppData\Local")),
            ("LocalAppDataLow", r(r"users\me\AppData\LocalLow")),
            ("UserProgramFiles", r(r"users\me\AppData\Local\Programs")),
            ("Programs", sm.join("Programs")),
            ("CommonPrograms", csm.join("Programs")),
            ("StartMenu", sm.clone()),
            ("CommonStartMenu", csm.clone()),
            ("Startup", sm.join(r"Programs\Startup")),
            ("CommonStartup", csm.join(r"Programs\Startup")),
            ("Desktop", r(r"users\me\Desktop")),
            ("PublicDesktop", r(r"users\Public\Desktop")),
            ("Documents", r(r"users\me\Documents")),
            ("Pictures", r(r"users\me\Pictures")),
            ("Videos", r(r"users\me\Videos")),
            ("Music", r(r"users\me\Music")),
            ("Downloads", r(r"users\me\Downloads")),
            ("SavedGames", r(r"users\me\Saved Games")),
            ("PublicDocuments", r(r"users\Public\Documents")),
            ("PublicDownloads", r(r"users\Public\Downloads")),
            ("PublicMusic", r(r"users\Public\Music")),
            ("PublicPictures", r(r"users\Public\Pictures")),
            ("PublicVideos", r(r"users\Public\Videos")),
        ]);
        let data_dir = r("data");
        let folders = Folders::build(&named, &data_dir).expect("sandbox folders are always complete");
        let base = format!(r"{TEST_KEY_PREFIX}\{tag}");
        let k = |name: &str, v: View| RegPath::new(Hive::Hkcu, v, format!(r"{base}\{name}"));
        Env {
            folders,
            uninstall_roots: vec![k("Uninstall", View::V64), k("Uninstall32", View::V32)],
            run_roots: vec![k("Run", View::V64)],
            app_paths_roots: vec![k("AppPaths", View::V64)],
            software_roots: vec![k("Software", View::V64)],
            data_dir,
            sandbox: true,
        }
    }

    /// `UNIINSTALLER_SANDBOX=<dir>` selects the sandbox; see `from_sandbox_var`.
    pub fn from_process_env() -> Result<Env> {
        Env::from_sandbox_var(std::env::var_os(SANDBOX_VAR))
    }

    /// Absent -> real system. Present (even empty) -> must be a local absolute existing directory with the
    /// marker file. It never falls back to the real system when the variable is present.
    pub fn from_sandbox_var(value: Option<OsString>) -> Result<Env> {
        let Some(v) = value else { return Env::system() };
        let bad = |why: &str| Err(Error(format!("{SANDBOX_VAR} is set but invalid: {why}")));
        let p = PathBuf::from(&v);
        if v.is_empty() {
            return bad("empty value");
        }
        if !is_local_abs(&p) {
            return bad("not a local absolute path");
        }
        if !p.is_dir() {
            return bad("directory does not exist");
        }
        if !p.join(SANDBOX_MARKER).is_file() {
            return bad("directory has no sandbox marker (run `uni sandbox-seed` first)");
        }
        Ok(Env::sandbox(&p, "sandbox"))
    }
}

pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty() && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Real Windows and System32 directories (the sandbox needs cmd.exe and msiexec.exe).
fn real_win_dirs() -> (PathBuf, PathBuf) {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    (root.clone(), root.join("System32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_var_validation() {
        let err = |v: Option<&str>| Env::from_sandbox_var(v.map(OsString::from)).unwrap_err().0;
        assert!(err(Some("")).contains("set but invalid"));
        assert!(err(Some("relative\\dir")).contains("set but invalid"));
        let t = tempfile::tempdir().unwrap();
        let missing = t.path().join("missing");
        assert!(err(Some(missing.to_str().unwrap())).contains("does not exist"));
        assert!(err(Some(t.path().to_str().unwrap())).contains("marker"));
        std::fs::write(t.path().join(SANDBOX_MARKER), b"").unwrap();
        let e = Env::from_sandbox_var(Some(t.path().as_os_str().to_owned())).unwrap();
        assert!(e.sandbox);
        // Env::sandbox canonicalizes the root, so compare against the canonical form (CI temp dirs are 8.3 paths).
        assert!(crate::paths::is_inside(&e.data_dir, &crate::paths::canonical(t.path()).unwrap()));
        // Absent variable -> the real system, read-only.
        let s = Env::from_sandbox_var(None).unwrap();
        assert!(!s.sandbox);
        assert!(s.data_dir.ends_with("uniinstaller-data"));
    }

    #[test]
    fn sandbox_has_no_windows_folder_and_real_system_dir() {
        let t = tempfile::tempdir().unwrap();
        let e = Env::sandbox(t.path(), "x1");
        assert!(!e.folders.windows_dir.starts_with(t.path()));
        assert!(!t.path().join("Windows").exists());
        assert!(e.uninstall_roots[0].path.contains("uniinstaller-tests"));
    }
}
