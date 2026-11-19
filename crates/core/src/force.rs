//! Forced removal ("remove by path"): a program the Windows program list does not know is named by the user; the scan then looks
//! for its leftovers around the picked folder and name. Nothing here ever runs a program or changes anything.
use crate::model::{Forced, InstalledApp};
use crate::paths::norm;
use crate::scan::name_variants;
use std::path::Path;

/// Ids of forced targets start with this; a listed program's id always starts with a hive (`HKLM64:`...), so they never collide.
pub const ID_PREFIX: &str = "force:";
/// A name shorter than this is used to look for settings only when it is exact evidence (spec 1.5).
pub const MIN_NAME: usize = 4;

/// Name variants usable to look for settings (spec 1.5: a short inexact name matches too much): each variant of
/// `scan::name_variants(name)` with at least MIN_NAME characters, or equal (any case) to exact evidence: the product name, the
/// picked exe's stem (exe pick) or the picked folder's name (folder pick). A parent folder's name is never evidence.
pub fn search_names(name: &str, picked: &Path, folder: Option<&Path>, product: Option<&str>) -> Vec<String> {
    let folder_pick = folder.is_some_and(|f| norm(f) == norm(picked));
    let own = if folder_pick { picked.file_name() } else { picked.file_stem() };
    let evidence: Vec<String> = own.map(|n| n.to_string_lossy().to_lowercase()).into_iter().chain(product.map(str::to_lowercase)).collect();
    name_variants(name).into_iter().filter(|v| v.chars().count() >= MIN_NAME || evidence.contains(&v.to_lowercase())).collect()
}

/// The stand-in `InstalledApp` the scan works on: no registry source, the install folder is the picked folder, and a file-only
/// pick names the file as the icon so scan section B offers it.
pub fn app_for(f: &Forced, name: &str, publisher: Option<&str>, version: Option<&str>) -> InstalledApp {
    InstalledApp {
        id: format!("{ID_PREFIX}{}", norm(&f.picked)),
        key_name: String::new(),
        sources: vec![],
        display_name: name.to_string(),
        display_version: version.map(str::to_string),
        publisher: publisher.map(str::to_string),
        install_location: f.folder.clone(),
        display_icon: f.folder.is_none().then(|| f.picked.display().to_string()),
        uninstall_string: None,
        quiet_uninstall_string: None,
        modify_path: None,
        install_date: None,
        estimated_size_kb: None,
        windows_installer: false,
        product_code: None,
        per_user: false,
        hidden: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn names(name: &str, picked: &str, folder: Option<&str>, product: Option<&str>) -> Vec<String> {
        search_names(name, &PathBuf::from(picked), folder.map(Path::new), product)
    }

    #[test]
    fn search_names_rule() {
        // Stop words and path characters are not usable at all.
        for n in ["App", "Tools", "Setup", "Update", "  ", r"Foo\Bar"] {
            assert!(names(n, r"C:\X\app.exe", None, None).is_empty(), "{n}");
        }
        // A short name is used only when it is exact evidence; a longer one always.
        assert_eq!(names("Abc 2", r"C:\X\other.exe", Some(r"C:\X"), None), vec!["Abc 2"], "the stripped `Abc` is 3 characters and not evidence");
        assert_eq!(names("Abc", r"C:\X\abc.exe", None, None), vec!["Abc"], "the exe's stem is evidence");
        assert!(names("Abc", r"C:\X\other.exe", None, None).is_empty());
        assert_eq!(names("Abc", r"C:\X\Abc", Some(r"C:\X\Abc"), None), vec!["Abc"], "the picked folder's name is evidence");
        // A parent folder's name is never evidence.
        assert!(names("Bin", r"C:\X\Bin\f2py.exe", Some(r"C:\X\Bin"), None).is_empty());
        assert!(names("Bin", r"C:\X\Bin\f2py.exe", None, None).is_empty());
        assert_eq!(names("f2py", r"C:\X\Bin\f2py.exe", None, None), vec!["f2py"]);
        assert_eq!(names("mpv", r"C:\Program Files\MPV\mpv.exe", Some(r"C:\Program Files\MPV"), Some("mpv")), vec!["mpv"]);
        assert_eq!(names("Lab Portable", r"C:\X\labportable.exe", None, None), vec!["Lab Portable"]);
    }

    #[test]
    fn app_for_shapes() {
        let f = Forced { picked: PathBuf::from(r"C:\X\a.exe"), folder: None, search_names: vec![] };
        let a = app_for(&f, "Foo", Some("Bar"), Some("1.0"));
        assert_eq!((a.id.as_str(), a.install_location.as_ref(), a.display_icon.as_deref(), a.sources.len()), ("force:c:\\x\\a.exe", None, Some(r"C:\X\a.exe"), 0));
        let f = Forced { picked: PathBuf::from(r"C:\X"), folder: Some(PathBuf::from(r"C:\X")), search_names: vec![] };
        let a = app_for(&f, "Foo", None, None);
        assert_eq!((a.install_location.as_deref(), a.display_icon.as_deref()), (Some(Path::new(r"C:\X")), None));
    }
}
