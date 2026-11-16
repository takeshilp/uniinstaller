//! Operations: describe, preview, uninstall flow, apply, restore, history.
use crate::command::parse_uninstall;
use crate::env::Env;
use crate::inventory::find_app;
use crate::model::*;
use crate::Result;

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
