//! Fake apps for tests, the CLI and the GUI demo: temp folders, a junction, .lnk files and keys under
//! `HKCU\Software\uniinstaller-tests\<tag>`. Nothing here touches the real system.
use crate::env::{Env, SANDBOX_MARKER, TEST_KEY_PREFIX, valid_tag};
use crate::model::RegPath;
use crate::paths::{canonical, is_local_abs, make_junction};
use crate::registry::{self, set_dword, set_string};
use crate::shortcuts;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use winreg::enums::*;

pub fn pf(env: &Env) -> PathBuf {
    env.folders.program_files[0].clone()
}
pub fn user_programs(env: &Env) -> PathBuf {
    env.folders.program_files[2].clone()
}
pub fn notes_dir(env: &Env) -> PathBuf {
    user_programs(env).join("Sandbox Notes")
}
/// "Sandbox Portable": a program no Uninstall entry knows (the forced-removal demo); see `seed`.
pub fn portable_dir(env: &Env) -> PathBuf {
    user_programs(env).join("Sandbox Portable")
}
pub fn suite_dir(env: &Env) -> PathBuf {
    pf(env).join("Sandbox Soft")
}
pub fn roaming(env: &Env) -> PathBuf {
    env.folders.app_data[0].clone()
}
pub fn documents(env: &Env) -> PathBuf {
    roaming(env).parent().and_then(Path::parent).expect("sandbox profile").join("Documents")
}
pub fn desktop(env: &Env) -> PathBuf {
    env.folders.desktops[0].clone()
}
pub fn start_menu(env: &Env) -> PathBuf {
    env.folders.start_menu[0].clone()
}
pub fn outside_dir(env: &Env) -> PathBuf {
    env.data_dir.parent().expect("sandbox root").join("outside")
}

fn write(p: &Path, content: &[u8]) -> Result<()> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(p, content)?;
    Ok(())
}

struct Entry<'a> {
    key: &'a str,
    name: Option<&'a str>,
    version: &'a str,
    publisher: &'a str,
    location: Option<&'a Path>,
    icon: Option<&'a Path>,
    uninstall: Option<String>,
}

fn register(env: &Env, e: &Entry, both_views: bool) -> Result<()> {
    let roots = if both_views { &env.uninstall_roots[..2] } else { &env.uninstall_roots[..1] };
    for root in roots {
        let k = registry::create(&root.child(e.key), KEY_ALL_ACCESS)?;
        if let Some(n) = e.name {
            set_string(&k, "DisplayName", n, false)?;
        }
        set_string(&k, "DisplayVersion", e.version, false)?;
        set_string(&k, "Publisher", e.publisher, false)?;
        if let Some(l) = e.location {
            set_string(&k, "InstallLocation", &l.to_string_lossy(), false)?;
        }
        if let Some(i) = e.icon {
            set_string(&k, "DisplayIcon", &i.to_string_lossy(), false)?;
        }
        if let Some(u) = &e.uninstall {
            // REG_EXPAND_SZ with %SystemRoot%, which also exercises expansion.
            set_string(&k, "UninstallString", u, true)?;
        }
    }
    Ok(())
}

fn hkcu(env: &Env, name: &str) -> String {
    // The reg.exe path of a key under the sandbox's Uninstall roots.
    let r = &env.uninstall_roots[0];
    let base = r.path.rsplit_once('\\').map(|x| x.0).unwrap_or("");
    format!(r"HKCU\{base}\{name}")
}

pub fn seed(root: &Path, tag: &str) -> Result<Env> {
    if !valid_tag(tag) {
        return Err(Error("invalid sandbox tag".into()));
    }
    fs::create_dir_all(root)?;
    let root = canonical(root)?;
    write(&root.join(SANDBOX_MARKER), b"uniinstaller sandbox\n")?;
    let env = Env::sandbox(&root, tag);
    let sr = "%SystemRoot%\\System32\\cmd.exe";

    // 1. Sandbox Notes: both views, files, junction, shortcuts, autorun, App Paths, settings.
    let nd = notes_dir(&env);
    let exe = nd.join("Sandbox Notes.exe");
    write(&exe, b"MZ fake")?;
    write(&nd.join(r"resources\app.dat"), b"data")?;
    write(&nd.join("config.ini"), b"[x]\n")?;
    write(&nd.join(r"logs\today.log"), b"log")?;
    write(&nd.join(r"Saves\slot1.sav"), b"save")?;
    let outside = outside_dir(&env);
    write(&outside.join("keep.txt"), b"keep me")?;
    make_junction(&nd.join("link-out"), &outside)?;
    let un = format!(
        r#"{sr} /c del /q "{exe}" & reg delete "{a}" /f & reg delete "{b}" /f"#,
        exe = exe.display(),
        a = hkcu(&env, "Uninstall\\SandboxNotes"),
        b = hkcu(&env, "Uninstall32\\SandboxNotes"),
    );
    register(&env, &Entry { key: "SandboxNotes", name: Some("Sandbox Notes"), version: "1.2.3", publisher: "Sandbox Soft", location: Some(&nd), icon: Some(&exe), uninstall: Some(un) }, true)?;
    let lnk_dir = start_menu(&env).join("Sandbox Soft");
    fs::create_dir_all(&lnk_dir)?;
    shortcuts::create(&lnk_dir.join("Sandbox Notes.lnk"), &exe)?;
    fs::create_dir_all(desktop(&env))?;
    shortcuts::create(&desktop(&env).join("Sandbox Notes.lnk"), &exe)?;
    let run = registry::create(&env.run_roots[0], KEY_ALL_ACCESS)?;
    set_string(&run, "SandboxNotes", &format!("\"{}\" --tray", exe.display()), false)?;
    let ap = registry::create(&env.app_paths_roots[0].child("Sandbox Notes.exe"), KEY_ALL_ACCESS)?;
    set_string(&ap, "", &exe.to_string_lossy(), false)?;
    let sw = registry::create(&env.software_roots[0].child("Sandbox Soft").child("Sandbox Notes"), KEY_ALL_ACCESS)?;
    set_string(&sw, "InstallDir", &nd.to_string_lossy(), false)?;
    write(&roaming(&env).join(r"Sandbox Soft\Sandbox Notes\settings.json"), b"{}")?;

    // 2. Sandbox Suite (parent of Shared Tool) with an unregistered foreign uninstaller dir.
    let sd = suite_dir(&env);
    write(&sd.join("suite.exe"), b"MZ fake")?;
    write(&sd.join(r"Portable Thing\unins000.exe"), b"")?;
    write(&sd.join(r"Portable Thing\data.bin"), b"bin")?;
    let un = format!(r#"{sr} /c del /q "{}" & reg delete "{}" /f"#, sd.join("suite.exe").display(), hkcu(&env, "Uninstall\\SandboxSuite"));
    register(&env, &Entry { key: "SandboxSuite", name: Some("Sandbox Suite"), version: "2.0", publisher: "Sandbox Soft", location: Some(&sd), icon: Some(&sd.join("suite.exe")), uninstall: Some(un) }, false)?;
    set_string(&run, "SandboxSuite", &format!("\"{}\"", sd.join("suite.exe").display()), false)?;

    // 3. Sandbox Shared Tool: the uninstaller leaves the key, so it stays "installed".
    let td = sd.join("Shared Tool");
    write(&td.join("tool.exe"), b"MZ fake")?;
    register(&env, &Entry { key: "SandboxSharedTool", name: Some("Sandbox Shared Tool"), version: "0.9", publisher: "Sandbox Soft", location: Some(&td), icon: Some(&td.join("tool.exe")), uninstall: Some(format!("{sr} /c exit 0")) }, false)?;

    // 4. Sandbox Orphan: a batch uninstaller that deletes the program and itself but leaves the key.
    let od = pf(&env).join("Orphan App");
    write(&od.join("orphan.exe"), b"MZ fake")?;
    write(&od.join("uninstall.bat"), b"@echo off\r\ndel /q \"%~dp0orphan.exe\"\r\n(goto) 2>nul & del \"%~f0\"\r\n")?;
    register(&env, &Entry { key: "SandboxOrphan", name: Some("Sandbox Orphan"), version: "3.1", publisher: "Orphan Inc.", location: Some(&od), icon: Some(&od.join("orphan.exe")), uninstall: Some(format!("\"{}\"", od.join("uninstall.bat").display())) }, false)?;

    // 5. Sandbox Broken: the uninstaller does not exist.
    register(&env, &Entry { key: "SandboxBroken", name: Some("Sandbox Broken"), version: "1.0", publisher: "Broken Ltd", location: None, icon: None, uninstall: Some(r"C:\nonexistent dir\un.exe /S".into()) }, false)?;

    // 6. Filter fixtures: system component, update (ParentKeyName), nameless.
    register(&env, &Entry { key: "SandboxSystemComponent", name: Some("Sandbox System Component"), version: "1", publisher: "x", location: None, icon: None, uninstall: None }, false)?;
    set_dword(&registry::create(&env.uninstall_roots[0].child("SandboxSystemComponent"), KEY_ALL_ACCESS)?, "SystemComponent", 1)?;
    register(&env, &Entry { key: "SandboxPatchKB1", name: Some("Sandbox Patch KB1"), version: "1", publisher: "x", location: None, icon: None, uninstall: None }, false)?;
    set_string(&registry::create(&env.uninstall_roots[0].child("SandboxPatchKB1"), KEY_ALL_ACCESS)?, "ParentKeyName", "Sandbox Notes", false)?;
    register(&env, &Entry { key: "SandboxNameless", name: None, version: "1", publisher: "x", location: None, icon: None, uninstall: None }, false)?;

    // 6b. Sandbox Portable: a program with no Uninstall entry (forced removal). Its folder holds an `unins000.cmd` that deletes the exe, and a
    // Start Menu link, a Run value, a settings folder and a vendorless key name it. None of them points into another seeded app.
    let pd = portable_dir(&env);
    let pexe = pd.join("portable.exe");
    write(&pexe, b"MZ fake")?;
    write(&pd.join(r"data\cache.bin"), b"cache")?;
    write(&pd.join("unins000.cmd"), format!("@echo off\r\ndel /q \"{}\"\r\n", pexe.display()).as_bytes())?;
    fs::create_dir_all(start_menu(&env))?;
    shortcuts::create(&start_menu(&env).join("Sandbox Portable.lnk"), &pexe)?;
    set_string(&run, "SandboxPortable", &format!("\"{}\"", pexe.display()), false)?;
    write(&roaming(&env).join(r"Sandbox Portable\settings.ini"), b"[x]\n")?;
    let psw = registry::create(&env.software_roots[0].child("Sandbox Portable"), KEY_ALL_ACCESS)?;
    set_string(&psw, "Path", &pd.to_string_lossy(), false)?;

    // 7. Sandbox Traced: a demo installer for install tracing. The values it overwrites exist before it runs; the two scripts in
    // `installers\` install and uninstall it. Nothing runs until the GUI or a test runs the setup script.
    let soft = &env.software_roots[0];
    set_string(&registry::create(&soft.child("Shared Soft").child("Common"), KEY_ALL_ACCESS)?, "Handler", r"C:\old\handler.exe", false)?;
    set_string(&registry::create(&soft.child("Other Soft").child("Updater"), KEY_ALL_ACCESS)?, "LastCheck", "old", false)?;
    set_string(&run, "SandboxTraced", r#""C:\old\traced-helper.exe""#, false)?;
    set_string(&registry::create(&env.app_paths_roots[0].child("shared-tool.exe"), KEY_ALL_ACCESS)?, "", r"C:\old\shared-tool.exe", false)?;
    write_traced_scripts(&env)?;
    Ok(env)
}

fn installers(env: &Env) -> PathBuf {
    env.data_dir.parent().expect("sandbox root").join("installers")
}

/// The demo installer's uninstall script.
pub fn traced_uninstall(env: &Env) -> PathBuf {
    installers(env).join("sandbox-traced-uninstall.cmd")
}

/// The demo installer: what the GUI's "trace an install" picks in sandbox mode, and what the trace tests run.
pub fn traced_setup(env: &Env) -> PathBuf {
    installers(env).join("sandbox-traced-setup.cmd")
}

/// Batch files with CRLF. cmd toggles its quote state on every `"`, and a path never holds `&`, so nothing special sits outside
/// quotes; reg.exe reads `\"` as a literal quote.
fn write_traced_scripts(env: &Env) -> Result<()> {
    let dir = pf(env).join(r"Trace Soft\Sandbox Traced");
    let exe = dir.join(r"bin\traced.exe");
    let un = format!(r"HKCU\{}", env.uninstall_roots[0].path);
    let (run, ap, sw) = (format!(r"HKCU\{}", env.run_roots[0].path), format!(r"HKCU\{}", env.app_paths_roots[0].path), format!(r"HKCU\{}", env.software_roots[0].path));
    let (own, runtime) = (format!(r"{un}\SandboxTraced"), format!(r"{un}\SandboxTracedRuntime"));
    let settings = roaming(env).join(r"Trace Soft\Sandbox Traced");
    let other = env.folders.program_files[1].join("Other Updater");
    let (dir, exe) = (dir.display(), exe.display());
    let uninstall = [
        "@echo off".to_string(),
        format!("del /q \"{exe}\""),
        format!("reg delete \"{own}\" /f >nul"),
        format!("reg delete \"{runtime}\" /f >nul"),
    ];
    write(&traced_uninstall(env), format!("{}\r\n", uninstall.join("\r\n")).as_bytes())?;
    let reg = |key: &str, args: &str| format!("reg add \"{key}\" {args} /f >nul");
    let setup = [
        "@echo off".to_string(),
        format!("mkdir \"{dir}\\bin\""),
        format!("echo MZ> \"{exe}\""),
        format!("echo x> \"{dir}\\data.bin\""),
        format!("copy /y \"{}\" \"{dir}\\uninstall.cmd\" >nul", traced_uninstall(env).display()),
        format!("mkdir \"{}\\Cache\"", settings.display()),
        format!("echo {{}}> \"{}\\settings.json\"", settings.display()),
        format!("echo x> \"{}\\Cache\\blob.bin\"", settings.display()),
        reg(&own, "/v DisplayName /d \"Sandbox Traced\""),
        reg(&own, "/v DisplayVersion /d 1.0"),
        reg(&own, "/v Publisher /d \"Trace Soft\""),
        reg(&own, &format!("/v InstallLocation /d \"{dir}\"")),
        reg(&own, &format!("/v DisplayIcon /d \"{exe}\"")),
        reg(&own, &format!("/v UninstallString /d \"\\\"{dir}\\uninstall.cmd\\\"\"")),
        // A hidden component: SystemComponent keeps it out of the program list.
        reg(&runtime, "/v DisplayName /d \"Sandbox Traced Runtime\""),
        reg(&runtime, "/v SystemComponent /t REG_DWORD /d 1"),
        // Overwrites a pre-existing value and points it at this program: offered as a revert.
        reg(&run, &format!("/v SandboxTraced /d \"\\\"{exe}\\\" /tray\"")),
        reg(&format!(r"{ap}\traced.exe"), &format!("/ve /d \"{exe}\"")),
        // Overwrites a pre-existing App Paths default: a revert, and the key itself must not be offered for deletion.
        reg(&format!(r"{ap}\shared-tool.exe"), &format!("/ve /d \"{exe}\"")),
        reg(&format!(r"{sw}\Trace Soft\Sandbox Traced"), &format!("/v InstallDir /d \"{dir}\"")),
        reg(&format!(r"{sw}\Shared Soft\Common"), &format!("/v Handler /d \"{exe}\"")),
        // Overwrites a value of another installed app (Sandbox Notes): blocked as SharedWithOtherApp.
        reg(&format!(r"{sw}\Sandbox Soft\Sandbox Notes"), &format!("/v InstallDir /d \"{dir}\"")),
        // Stands in for a background writer: unrelated to this program, so neither preselected nor reverted.
        format!("mkdir \"{}\"", other.display()),
        format!("echo x> \"{}\\update.dat\"", other.display()),
        reg(&format!(r"{sw}\Other Soft\Updater"), "/v LastCheck /d new"),
    ];
    write(&traced_setup(env), format!("{}\r\n", setup.join("\r\n")).as_bytes())
}

/// Removes the sandbox registry subtree and the root folder. Refuses unless the root carries the marker.
pub fn clean(root: &Path, tag: &str) -> Result<()> {
    if !valid_tag(tag) {
        return Err(Error("invalid sandbox tag".into()));
    }
    if !is_local_abs(root) || !root.join(SANDBOX_MARKER).is_file() {
        return Err(Error(format!("refusing to clean {}: no sandbox marker", root.display())));
    }
    let key = RegPath::new(crate::model::Hive::Hkcu, crate::model::View::V64, format!(r"{TEST_KEY_PREFIX}\{tag}"));
    match registry::delete_key(&key) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // std remove_dir_all does not follow junctions.
    fs::remove_dir_all(root)?;
    Ok(())
}
