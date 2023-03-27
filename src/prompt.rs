// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

//use pinentry_rs;
use crate::error::R;
use pinentry;
use secrecy::SecretString;
use std::sync::mpsc::Receiver;

pub trait Prompt {
    fn yes_or_no_p(&self, prompt: &str) -> Receiver<Result<bool, String>>;
}

pub struct Pinentry;

// FIXME: report report this as bug to the pinentry_rs maintainer.
fn escape_string(s: &str) -> String {
    //s.replace("\n", "%0A")
    s.into()
}

impl Prompt for Pinentry {
    fn yes_or_no_p(&self, prompt: &str) -> Receiver<Result<bool, String>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let escaped = escape_string(prompt);
        std::thread::spawn(move || {
            let mut d =
                match pinentry::ConfirmationDialog::with_default_binary() {
                    Some(d) => d,
                    None => {
                        return sender.send(Err(
                            "pinentry cannot be found in PATH".into(),
                        ))
                    }
                };
            let msg: Result<bool, String> = d
                .with_ok("Yes")
                .with_cancel("No")
                .confirm(&escaped)
                .map_err(|e| e.to_string());
            sender.send(msg)
        });
        receiver
    }
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
