use std::{collections::HashMap, env, ops::Deref};

use anyhow::bail;
use clap::{Args, Parser, Subcommand};
use rpassword::prompt_password;
use secret_service::blocking::{Item, SecretService};

#[derive(Parser, Debug)]
#[command(about)]
struct App {
    #[command(subcommand)]
    pub cmd: Cmd,

    #[arg(alias = "n")]
    pub namespace: Option<String>,
}

#[derive(Args, Debug)]
pub struct Set {
    pub key: String,

    #[arg(long, short = 'v')]
    pub value: Option<String>,
}

#[derive(Args, Debug)]
pub struct Get {
    pub key: String,
}

#[derive(Args, Debug)]
pub struct Env {
    pub keys: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Write a secret to the keystore
    Set(Set),
    /// Read a secret from the keystore
    Get(Get),
    /// Read a set of secrets from the keystore and print `export ENV_NAME=secret_value` lines to stdout
    Env(Env),
    /// Export all secrets in the namespace as `env-secrets set` commands
    Export,
}

fn main() {
    if let Err(e) = app() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn app() -> anyhow::Result<()> {
    let app = App::parse();
    let namespace = match app.namespace {
        Some(ref namespace) => namespace.to_string(),
        None => std::env::current_dir()?
            .file_name()
            .ok_or(anyhow::anyhow!("Unable to get current directory"))?
            .to_string_lossy()
            .to_string(),
    };

    let ss = SecretService::connect(secret_service::EncryptionType::Dh)?;
    let collection = ss.get_default_collection()?;

    match &app.cmd {
        Cmd::Set(set) => {
            validate_keys(&[set.key.as_str()])?;

            let password = match set.value.clone() {
                Some(value) => value,
                None => prompt_password("Password: ")?,
            };

            collection.create_item(
                &format!("env-secrets/{namespace}/{key}", key = &set.key),
                HashMap::from([
                    ("app", "env-secrets"),
                    ("namespace", &namespace),
                    ("env", &set.key),
                ]),
                password.as_bytes(),
                true,
                "text/plain",
            )?;
        }
        Cmd::Get(get) => {
            validate_keys(&[get.key.as_str()])?;

            let found = collection.search_items(HashMap::from([
                ("app", "env-secrets"),
                ("namespace", &namespace),
                ("env", &get.key),
            ]))?;

            let found = found.first().ok_or(anyhow::anyhow!("No secrets found"))?;
            if found.is_locked()? {
                found.unlock()?;
            }

            let secret = String::from_utf8(found.get_secret()?)?;

            println!("{secret}");
        }
        Cmd::Env(env) => {
            validate_keys(&env.keys)?;

            let found = ss.search_items(HashMap::from([
                ("app", "env-secrets"),
                ("namespace", &namespace),
            ]))?;

            let mut items = vec![];

            let filter = |key: &String| env.keys.contains(key);
            collect_items(&mut items, found.locked, filter, true)?;
            collect_items(&mut items, found.unlocked, filter, false)?;

            let locked = items
                .iter()
                .filter(|(locked, _, _)| *locked)
                .map(|(_, _, item)| item)
                .collect::<Vec<_>>();

            ss.unlock_all(&locked)?;

            for (_, env, item) in &items {
                let secret = String::from_utf8(item.get_secret()?)?;
                let secret = secret.replace('\'', "'\''");

                println!("export {env}='{secret}'");
            }
        }
        Cmd::Export => {
            let found = ss.search_items(HashMap::from([
                ("app", "env-secrets"),
                ("namespace", &namespace),
            ]))?;

            let mut items = vec![];
            collect_items(&mut items, found.locked, |_| true, true)?;
            collect_items(&mut items, found.unlocked, |_| true, false)?;

            let locked = items
                .iter()
                .filter(|(locked, _, _)| *locked)
                .map(|(_, _, item)| item)
                .collect::<Vec<_>>();

            ss.unlock_all(&locked)?;

            let exe = env::current_exe()?;
            let exe = exe
                .file_name()
                .ok_or(anyhow::anyhow!("Unable to get executable name"))?;

            for (_, env, item) in &items {
                let secret = String::from_utf8(item.get_secret()?)?;
                let secret = secret.replace('\'', "'\''");

                println!(
                    "{exe} -n {namespace} set {env} -v '{secret}'",
                    exe = exe.to_string_lossy(),
                );
            }
        }
    }

    Ok(())
}

fn collect_items<'a>(
    acc: &mut Vec<(bool, String, Item<'a>)>,
    items: Vec<Item<'a>>,
    filter: impl Fn(&String) -> bool,
    locked: bool,
) -> anyhow::Result<()> {
    for item in items {
        let Some(key) = item.get_attributes()?.remove("env") else {
            continue;
        };

        if !filter(&key) {
            continue;
        }

        acc.push((locked, key, item));
    }

    Ok(())
}

fn validate_keys(keys: &[impl Deref<Target = str>]) -> anyhow::Result<()> {
    for key in keys {
        let key = &**key;
        if !is_valid_key(key) {
            bail!("Invalid key: `{key}`");
        }
    }

    Ok(())
}

fn is_valid_key(key: &str) -> bool {
    if !key.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return false;
    }

    key.chars()
        .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_'))
}
