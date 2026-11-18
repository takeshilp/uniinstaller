//! View-aware registry access, structured capture and restore.
//! Every open and create passes the WOW64 view flag; paths never contain `Wow6432Node`.
// shortcut: backups hold values, types, subkeys and view only; no ACLs, class names or volatile keys, and
// restored keys get default ACLs. Upgrade if a restore ever needs security descriptors.
use crate::model::*;
use std::borrow::Cow;
use std::io;
use winreg::RegKey;
use winreg::RegValue;
use winreg::enums::*;
use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows::core::PCWSTR;

pub const MAX_NODES: usize = 5000;

fn hive_key(h: Hive) -> RegKey {
    RegKey::predef(match h {
        Hive::Hklm => HKEY_LOCAL_MACHINE,
        Hive::Hkcu => HKEY_CURRENT_USER,
    })
}

fn view_flag(v: View) -> u32 {
    match v {
        View::V64 => KEY_WOW64_64KEY,
        View::V32 => KEY_WOW64_32KEY,
    }
}

pub fn open(p: &RegPath, access: u32) -> io::Result<RegKey> {
    hive_key(p.hive).open_subkey_with_flags(&p.path, access | view_flag(p.view))
}

/// Creates the key (and parents) if missing, or opens it.
pub fn create(p: &RegPath, access: u32) -> io::Result<RegKey> {
    Ok(hive_key(p.hive).create_subkey_with_flags(&p.path, access | view_flag(p.view))?.0)
}

pub fn exists(p: &RegPath) -> bool {
    open(p, KEY_READ).is_ok()
}

pub fn expand_env(s: &str) -> String {
    let w: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `w` is NUL-terminated; the buffer is sized by the first call.
    unsafe {
        let n = ExpandEnvironmentStringsW(PCWSTR(w.as_ptr()), None);
        if n == 0 {
            return s.to_string();
        }
        let mut buf = vec![0u16; n as usize];
        let m = ExpandEnvironmentStringsW(PCWSTR(w.as_ptr()), Some(&mut buf));
        if m == 0 || m as usize > buf.len() {
            return s.to_string();
        }
        String::from_utf16_lossy(&buf[..(m as usize).saturating_sub(1)])
    }
}

fn decode_utf16(bytes: &[u8]) -> String {
    let u: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    String::from_utf16_lossy(&u).trim_end_matches('\0').to_string()
}

/// REG_SZ / REG_EXPAND_SZ as text; `expand` runs environment expansion (harmless on plain REG_SZ).
pub fn read_string(k: &RegKey, name: &str, expand: bool) -> Option<String> {
    let v = k.get_raw_value(name).ok()?;
    match v.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
            let s = decode_utf16(&v.bytes);
            Some(if expand { expand_env(&s) } else { s })
        }
        _ => None,
    }
}

/// Text of a captured REG_SZ / REG_EXPAND_SZ (expanded, like `read_string(.., true)`) or REG_MULTI_SZ (one item per line).
pub fn val_text(v: &RegVal) -> Option<String> {
    let s = decode_utf16(&v.data);
    match to_regtype(v.kind)? {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => Some(expand_env(&s)),
        RegType::REG_MULTI_SZ => Some(s.replace('\0', "\n")),
        _ => None,
    }
}

pub fn read_dword(k: &RegKey, name: &str) -> Option<u32> {
    let v = k.get_raw_value(name).ok()?;
    match v.vtype {
        RegType::REG_DWORD if v.bytes.len() == 4 => Some(u32::from_le_bytes([v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3]])),
        _ => None,
    }
}

pub fn set_string(k: &RegKey, name: &str, value: &str, expand: bool) -> io::Result<()> {
    let bytes: Vec<u8> = value.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect();
    let vtype = if expand { RegType::REG_EXPAND_SZ } else { RegType::REG_SZ };
    k.set_raw_value(name, &RegValue { bytes: Cow::Owned(bytes), vtype })
}

pub fn set_dword(k: &RegKey, name: &str, value: u32) -> io::Result<()> {
    k.set_raw_value(name, &RegValue { bytes: Cow::Owned(value.to_le_bytes().to_vec()), vtype: RegType::REG_DWORD })
}

/// `winreg::RegType` has no `TryFrom<u32>`.
pub fn to_regtype(k: u32) -> Option<RegType> {
    Some(match k {
        0 => RegType::REG_NONE,
        1 => RegType::REG_SZ,
        2 => RegType::REG_EXPAND_SZ,
        3 => RegType::REG_BINARY,
        4 => RegType::REG_DWORD,
        5 => RegType::REG_DWORD_BIG_ENDIAN,
        6 => RegType::REG_LINK,
        7 => RegType::REG_MULTI_SZ,
        8 => RegType::REG_RESOURCE_LIST,
        9 => RegType::REG_FULL_RESOURCE_DESCRIPTOR,
        10 => RegType::REG_RESOURCE_REQUIREMENTS_LIST,
        11 => RegType::REG_QWORD,
        _ => return None,
    })
}

pub(crate) fn to_val(name: String, v: RegValue<'_>) -> RegVal {
    RegVal { name, kind: v.vtype as u32, data: v.bytes.to_vec() }
}

fn leaf(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

fn capture_key(k: &RegKey, name: &str, count: &mut usize) -> io::Result<RegNode> {
    let too_large = || io::Error::new(io::ErrorKind::FileTooLarge, "registry key has more than 5000 values and subkeys");
    let mut values = Vec::new();
    for item in k.enum_values() {
        let (n, v) = item?; // a value type above 11 surfaces here as ERROR_BAD_FILE_TYPE
        *count += 1;
        if *count > MAX_NODES {
            return Err(too_large());
        }
        values.push(to_val(n, v));
    }
    values.sort_by_key(|v| v.name.to_lowercase());
    let mut names = k.enum_keys().collect::<io::Result<Vec<String>>>()?;
    names.sort_by_key(|n| n.to_lowercase());
    let mut keys = Vec::new();
    for n in names {
        *count += 1;
        if *count > MAX_NODES {
            return Err(too_large());
        }
        let sub = k.open_subkey_with_flags(&n, KEY_READ)?; // the view is inherited from the parent handle
        keys.push(capture_key(&sub, &n, count)?);
    }
    Ok(RegNode { name: name.to_string(), values, keys })
}

/// Recursive snapshot. Over `MAX_NODES` values plus keys returns `ErrorKind::FileTooLarge`.
pub fn capture(p: &RegPath) -> io::Result<RegNode> {
    let k = open(p, KEY_READ)?;
    capture_key(&k, leaf(&p.path), &mut 0)
}

/// Merge semantics: recreate keys, set a value only if it is absent.
pub fn restore_node(p: &RegPath, node: &RegNode) -> io::Result<()> {
    let k = create(p, KEY_ALL_ACCESS)?;
    restore_into(&k, node)
}

fn restore_into(k: &RegKey, node: &RegNode) -> io::Result<()> {
    for v in &node.values {
        let Some(t) = to_regtype(v.kind) else { return Err(io::Error::other("unknown value type in backup")) };
        match k.get_raw_value(&v.name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                k.set_raw_value(&v.name, &RegValue { bytes: Cow::Borrowed(&v.data), vtype: t })?;
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
    }
    for sub in &node.keys {
        let (child, _) = k.create_subkey_with_flags(&sub.name, KEY_ALL_ACCESS)?;
        restore_into(&child, sub)?;
    }
    Ok(())
}

pub fn delete_key(p: &RegPath) -> io::Result<()> {
    let (parent, name) = match p.path.rsplit_once('\\') {
        Some((a, b)) => (RegPath::new(p.hive, p.view, a), b),
        None => (RegPath::new(p.hive, p.view, ""), p.path.as_str()),
    };
    open(&parent, KEY_ALL_ACCESS)?.delete_subkey_all(name)
}

pub fn read_value(p: &RegPath, name: &str) -> io::Result<RegVal> {
    let v = open(p, KEY_READ)?.get_raw_value(name)?;
    Ok(to_val(name.to_string(), v))
}

pub fn delete_value(p: &RegPath, name: &str) -> io::Result<()> {
    open(p, KEY_ALL_ACCESS)?.delete_value(name)
}

/// Overwrites a value in an existing key; never creates the key.
pub fn write_value(p: &RegPath, val: &RegVal) -> io::Result<()> {
    let Some(t) = to_regtype(val.kind) else { return Err(io::Error::other("unknown value type")) };
    open(p, KEY_SET_VALUE)?.set_raw_value(&val.name, &RegValue { bytes: Cow::Borrowed(&val.data), vtype: t })
}

/// Kind and data only (the name is the lookup key).
pub fn same_data(a: &RegVal, b: &RegVal) -> bool {
    a.kind == b.kind && a.data == b.data
}

/// Sets the value only if absent; if present, equal -> Restored, different -> Conflict.
pub fn restore_value(p: &RegPath, val: &RegVal) -> io::Result<RestoreStatus> {
    let Some(t) = to_regtype(val.kind) else { return Err(io::Error::other("unknown value type in backup")) };
    let k = create(p, KEY_ALL_ACCESS)?;
    match k.get_raw_value(&val.name) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            k.set_raw_value(&val.name, &RegValue { bytes: Cow::Borrowed(&val.data), vtype: t })?;
            Ok(RestoreStatus::Restored)
        }
        Err(e) => Err(e),
        Ok(cur) => Ok(if cur.vtype as u32 == val.kind && cur.bytes.as_ref() == val.data.as_slice() { RestoreStatus::Restored } else { RestoreStatus::Conflict }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_key(tag: &str) -> RegPath {
        RegPath::new(Hive::Hkcu, View::V64, format!(r"Software\uniinstaller-tests\{tag}\unit"))
    }

    fn cleanup(p: &RegPath) {
        let _ = delete_key(&RegPath::new(p.hive, p.view, format!(r"Software\uniinstaller-tests\{}", p.path.split('\\').nth(2).unwrap())));
    }

    #[test]
    fn capture_delete_restore_roundtrip_all_types() {
        let p = test_key(&format!("reg_rt_{}", std::process::id()));
        let k = create(&p, KEY_ALL_ACCESS).unwrap();
        set_string(&k, "", "default", false).unwrap();
        set_string(&k, "sz", "text", false).unwrap();
        set_string(&k, "exp", r"%SystemRoot%\x", true).unwrap();
        set_dword(&k, "dw", 7).unwrap();
        k.set_raw_value("multi", &RegValue { bytes: Cow::Owned(vec![97, 0, 0, 0, 98, 0, 0, 0, 0, 0]), vtype: RegType::REG_MULTI_SZ }).unwrap();
        k.set_raw_value("qw", &RegValue { bytes: Cow::Owned(vec![1, 2, 3, 4, 5, 6, 7, 8]), vtype: RegType::REG_QWORD }).unwrap();
        k.set_raw_value("bin", &RegValue { bytes: Cow::Owned(vec![0, 255, 1]), vtype: RegType::REG_BINARY }).unwrap();
        let (sub, _) = k.create_subkey("Sub\\Deeper").unwrap();
        set_string(&sub, "v", "1", false).unwrap();
        let before = capture(&p).unwrap();
        let text = |n: &str| before.values.iter().find(|v| v.name == n).and_then(val_text);
        assert_eq!(text("multi").as_deref(), Some("a\nb"));
        assert_eq!(text("exp"), Some(expand_env(r"%SystemRoot%\x")));
        assert_eq!(text("dw"), None);
        assert_eq!(before.values.len(), 7);
        assert_eq!(before.keys[0].keys[0].name, "Deeper");
        delete_key(&p).unwrap();
        assert!(!exists(&p));
        restore_node(&p, &before).unwrap();
        assert_eq!(capture(&p).unwrap(), before);
        // merge: an existing different value is not overwritten
        set_string(&open(&p, KEY_ALL_ACCESS).unwrap(), "sz", "changed", false).unwrap();
        restore_node(&p, &before).unwrap();
        assert_eq!(read_string(&open(&p, KEY_READ).unwrap(), "sz", false).unwrap(), "changed");
        // single value ops
        let v = read_value(&p, "dw").unwrap();
        delete_value(&p, "dw").unwrap();
        assert_eq!(restore_value(&p, &v).unwrap(), RestoreStatus::Restored);
        assert_eq!(restore_value(&p, &v).unwrap(), RestoreStatus::Restored);
        let mut other = v.clone();
        other.data = vec![9, 0, 0, 0];
        assert_eq!(restore_value(&p, &other).unwrap(), RestoreStatus::Conflict);
        cleanup(&p);
    }

    #[test]
    fn write_value_never_creates_keys() {
        let p = test_key(&format!("reg_wv_{}", std::process::id()));
        let val = |data: &str| RegVal { name: "v".into(), kind: 1, data: data.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect() };
        assert_eq!(write_value(&p, &val("x")).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(!exists(&p), "a missing key is not created");
        let k = create(&p, KEY_ALL_ACCESS).unwrap();
        set_string(&k, "v", "old", false).unwrap();
        write_value(&p, &val("new")).unwrap();
        assert!(same_data(&read_value(&p, "v").unwrap(), &val("new")));
        assert!(!same_data(&read_value(&p, "v").unwrap(), &val("old")));
        write_value(&p, &RegVal { name: "fresh".into(), ..val("n") }).unwrap();
        assert!(read_value(&p, "fresh").is_ok(), "a missing value in an existing key is created");
        assert!(write_value(&p, &RegVal { kind: 99, ..val("n") }).is_err(), "an unknown type is refused");
        let mut other = val("new");
        other.kind = 2;
        assert!(!same_data(&other, &val("new")), "the kind counts");
        cleanup(&p);
    }

    #[test]
    fn expand_env_expands() {
        let sr = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand_env(r"%SystemRoot%\x"), format!(r"{sr}\x"));
        assert_eq!(expand_env("plain"), "plain");
    }

    #[test]
    fn regtype_mapping() {
        for i in 0..=11u32 {
            assert_eq!(to_regtype(i).unwrap() as u32, i);
        }
        assert!(to_regtype(12).is_none());
    }
}
