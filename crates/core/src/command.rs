//! UninstallString -> Launch. Longest-first prefix probing over absolute paths only; msiexec is rewritten to /X.
use crate::model::Launch;
use crate::paths::is_local_abs;
use crate::registry::expand_env;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::core::PCWSTR;

const EXE_EXT: &[&str] = &["exe", "com", "bat", "cmd"];

/// A bare name (no `\`) resolves only to `system_dir\<name>`, never through the CWD or PATH.
fn resolve_bare(token: &str, system_dir: &Path, exists: &dyn Fn(&Path) -> bool) -> Option<PathBuf> {
    if token.contains(['\\', '/']) {
        return None;
    }
    let name = if Path::new(token).extension().is_some() { token.to_string() } else { format!("{token}.exe") };
    let p = system_dir.join(name);
    exists(&p).then_some(p)
}

/// Splits a command line into the executable and the verbatim tail. Pure: the filesystem is behind `exists`.
pub fn split_command(s: &str, system_dir: &Path, exists: &dyn Fn(&Path) -> bool) -> Result<(PathBuf, String), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".into());
    }
    let (exe, tail) = if let Some(rest) = s.strip_prefix('"') {
        let end = rest.find('"').ok_or("unbalanced quote")?;
        let first = &rest[..end];
        let tail = rest[end + 1..].trim_start().to_string();
        let p = PathBuf::from(first);
        if is_local_abs(&p) {
            (p, tail)
        } else {
            (resolve_bare(first, system_dir, exists).ok_or("executable not found")?, tail)
        }
    } else {
        // Probe from the longest prefix to the shortest, so `C:\Program Files\x.exe` never resolves to `C:\Program`.
        let mut cuts: Vec<usize> = s.match_indices(' ').map(|(i, _)| i).collect();
        cuts.push(s.len());
        let mut found = None;
        for &c in cuts.iter().rev() {
            let prefix = Path::new(&s[..c]);
            if is_local_abs(prefix) && exists(prefix) {
                found = Some((prefix.to_path_buf(), s[c..].trim_start().to_string()));
                break;
            }
        }
        match found {
            Some(f) => f,
            None => {
                let (tok, tail) = s.split_once(' ').unwrap_or((s, ""));
                (resolve_bare(tok, system_dir, exists).ok_or("executable not found")?, tail.trim_start().to_string())
            }
        }
    };
    let ok = exe.extension().and_then(|e| e.to_str()).is_some_and(|e| EXE_EXT.contains(&e.to_lowercase().as_str()));
    if !ok {
        return Err("unsupported executable type".into());
    }
    Ok((exe, tail))
}

/// First `{8-4-4-4-12}` GUID in `s`.
fn find_guid(s: &str) -> Option<String> {
    (0..s.len().saturating_sub(37)).find_map(|i| {
        let w = s.get(i..i + 38)?;
        let wb = w.as_bytes();
        let ok = wb[0] == b'{'
            && wb[37] == b'}'
            && [9, 14, 19, 24].iter().all(|&k| wb[k] == b'-')
            && w[1..37].chars().enumerate().all(|(j, c)| [8, 13, 18, 23].contains(&j) || c.is_ascii_hexdigit());
        ok.then(|| w.to_string())
    })
}

fn argv_of(tail: &str) -> Vec<String> {
    if tail.trim().is_empty() {
        return vec![];
    }
    // The dummy program name makes the first token follow the program-name rules, and an empty string
    // would make the API return the current exe path.
    let w: Vec<u16> = format!("x {tail}").encode_utf16().chain(std::iter::once(0)).collect();
    let mut n = 0i32;
    // SAFETY: the returned array is read within bounds and freed with LocalFree.
    unsafe {
        let p = CommandLineToArgvW(PCWSTR(w.as_ptr()), &mut n);
        if p.is_null() {
            return vec![];
        }
        let out = (1..n as usize).map(|i| (*p.add(i)).to_string().unwrap_or_default()).collect();
        let _ = LocalFree(Some(HLOCAL(p as *mut _)));
        out
    }
}

/// `expand_env` is applied by the caller; `exists` decides what counts as an existing file.
pub fn parse_with(raw: &str, system_dir: &Path, product_code: Option<&str>, exists: &dyn Fn(&Path) -> bool) -> Result<Launch, String> {
    let (mut exe, mut tail) = split_command(raw, system_dir, exists)?;
    let mut msi_product = None;
    let stem = exe.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    if stem == "msiexec" {
        exe = system_dir.join("msiexec.exe");
        let guid = find_guid(&tail).or_else(|| product_code.map(str::to_string)).ok_or("msiexec command without a product code")?;
        // Never /quiet or /norestart. /X also turns a /I modify or repair command into removal.
        tail = format!("/X{guid}");
        msi_product = Some(guid);
    }
    if !exists(&exe) {
        return Err("executable not found".into());
    }
    let argv = argv_of(&tail);
    Ok(Launch { raw: raw.to_string(), exe, args: tail, argv, msi_product })
}

/// Real filesystem and environment expansion. `QuietUninstallString` is never used.
pub fn parse_uninstall(raw: &str, system_dir: &Path, product_code: Option<&str>) -> Result<Launch, String> {
    let mut l = parse_with(&expand_env(raw), system_dir, product_code, &|p| p.is_file())?;
    l.raw = raw.to_string();
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const SYS: &str = r"C:\Windows\System32";
    fn fs(files: &[&str]) -> impl Fn(&Path) -> bool {
        let set: HashSet<String> = files.iter().map(|f| f.to_lowercase()).collect();
        move |p: &Path| {
            assert!(is_local_abs(p), "exists() called with a relative path: {}", p.display());
            set.contains(&p.to_string_lossy().to_lowercase())
        }
    }
    fn split(s: &str, files: &[&str]) -> Result<(PathBuf, String), String> {
        split_command(s, Path::new(SYS), &fs(files))
    }

    #[test]
    fn split_quoted() {
        let (e, t) = split(r#""C:\Program Files\A\un.exe" /S /D="x y""#, &[]).unwrap();
        assert_eq!(e, PathBuf::from(r"C:\Program Files\A\un.exe"));
        assert_eq!(t, r#"/S /D="x y""#);
    }

    #[test]
    fn split_unquoted_longest_prefix() {
        let (e, t) = split(r"C:\Program Files\A B\un.exe /S", &[r"C:\Program Files\A B\un.exe"]).unwrap();
        assert_eq!(e, PathBuf::from(r"C:\Program Files\A B\un.exe"));
        assert_eq!(t, "/S");
    }

    #[test]
    fn split_prefers_longest_over_c_program_trap() {
        // `C:\Program.exe` exists as a hijack file; the real exe is longer.
        let files = [r"C:\Program.exe", r"C:\Program Files\A\un.exe"];
        let (e, _) = split(r"C:\Program Files\A\un.exe -x", &files).unwrap();
        assert_eq!(e, PathBuf::from(r"C:\Program Files\A\un.exe"));
        assert!(split(r"C:\Program Files\A\un.exe -x", &[r"C:\Program"]).is_err());
    }

    #[test]
    fn bare_name_resolves_to_system_dir() {
        let (e, t) = split("cmd /c exit 0", &[r"C:\Windows\System32\cmd.exe"]).unwrap();
        assert_eq!(e, PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        assert_eq!(t, "/c exit 0");
        assert_eq!(split("nothere /x", &[]).unwrap_err(), "executable not found");
    }

    #[test]
    fn empty_and_unbalanced() {
        assert_eq!(split("  ", &[]).unwrap_err(), "empty");
        assert_eq!(split(r#""C:\a\b.exe /S"#, &[]).unwrap_err(), "unbalanced quote");
    }

    #[test]
    fn rejects_unsupported_extension() {
        assert_eq!(split(r"C:\a\b.msi /x", &[r"C:\a\b.msi"]).unwrap_err(), "unsupported executable type");
        assert_eq!(split(r#""C:\a\b.dll""#, &[]).unwrap_err(), "unsupported executable type");
    }

    #[test]
    fn relative_prefix_never_probed() {
        // The fake `exists` panics on a relative path; none must be probed.
        assert!(split(r"setup\un.exe /S", &[]).is_err());
        assert!(split(r"..\un.exe", &[]).is_err());
        assert!(split(r"sub dir\un.exe /S", &[]).is_err());
        assert_eq!(split(r#""un.exe" /S"#, &[]).unwrap_err(), "executable not found");
    }

    #[test]
    fn msiexec_i_becomes_x() {
        let g = "{8B1E2B3A-0000-4C4C-9999-ABCDEF012345}";
        let files = [r"C:\Windows\System32\msiexec.exe"];
        for raw in [format!("MsiExec.exe /I{g}"), format!("msiexec /i {g} /quiet /norestart"), format!("msiexec.exe /X{g}")] {
            let l = parse_with(&raw, Path::new(SYS), None, &fs(&files)).unwrap();
            assert_eq!(l.args, format!("/X{g}"));
            assert_eq!(l.msi_product.as_deref(), Some(g));
            assert_eq!(l.exe, PathBuf::from(r"C:\Windows\System32\msiexec.exe"));
            assert_eq!(l.argv, vec![format!("/X{g}")]);
        }
    }

    #[test]
    fn msiexec_without_guid_uses_product_code_or_errors() {
        let files = [r"C:\Windows\System32\msiexec.exe"];
        let g = "{8B1E2B3A-0000-4C4C-9999-ABCDEF012345}";
        let l = parse_with("msiexec.exe /i package.msi", Path::new(SYS), Some(g), &fs(&files)).unwrap();
        assert_eq!(l.args, format!("/X{g}"));
        assert_eq!(parse_with("msiexec.exe /i package.msi", Path::new(SYS), None, &fs(&files)).unwrap_err(), "msiexec command without a product code");
    }

    #[test]
    fn argv_of_tail() {
        assert_eq!(argv_of(r#"/S "C:\a b\c" x\"y"#), vec!["/S", r"C:\a b\c", "x\"y"]);
        assert!(argv_of("").is_empty());
    }

    #[test]
    fn parse_uninstall_real_cmd() {
        let sys = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
        let l = parse_uninstall(r"%SystemRoot%\System32\cmd.exe /c exit 0", &sys, None).unwrap();
        assert_eq!(l.args, "/c exit 0");
        assert_eq!(l.raw, r"%SystemRoot%\System32\cmd.exe /c exit 0");
        assert!(parse_uninstall(r"C:\nonexistent dir\un.exe /S", &sys, None).is_err());
    }
}
