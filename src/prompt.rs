// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

//use pinentry_rs;
use crate::error::R;
use pinentry;
use secrecy::SecretString;

// FIXME: report report this as bug to the pinentry_rs maintainer.
fn escape_string(s: &str) -> String {
    s.replace("\n", "%0A")
    //s.into()
}

pub fn yes_or_no_p(prompt: &str) -> Result<bool, String> {
    let escaped = escape_string(prompt);
    let mut dialog =
        match pinentry::ConfirmationDialog::with_default_binary() {
            Some(d) => d,
            None => return Err("pinentry cannot be found in PATH".into()),
        };
    dialog
        .with_ok("Yes")
        .with_cancel("No")
        .confirm(&escaped)
        .map_err(|e| format!("{:?}", e))
}

pub fn read_pin(prompt: &str) -> R<SecretString> {
    let mut d = pinentry::PassphraseInput::with_default_binary()
        .ok_or_else(|| {
            "read_pin failed: pinentry cannot be found in PATH".to_string()
        })?;
    d.with_description(&escape_string(prompt))
        .with_prompt("")
        .interact()
        .map_err(|e| e.to_string().into())
}
