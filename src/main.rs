use std::ops::Deref;

use anyhow::bail;
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(about, version)]
struct App {
    #[command(subcommand)]
    pub cmd: Cmd,

    /// Namespace for the environment. Used to logically group secrets, like `project1/prod` and `project1/dev`.
    /// Defaults to the current directory name.
    pub namespace: Option<String>,
}

#[derive(Args, Debug)]
pub struct Set {
    /// Environment variable name
    pub key: String,

    /// Secret value
    #[arg(long, short = 'v')]
    pub value: Option<String>,
}

#[derive(Args, Debug)]
pub struct Get {
    pub key: String,
}

#[derive(Args, Debug)]
pub struct Env {
    /// Environment variables to export. If no keys provided, all the secrets in the namespace will be exported.
    pub keys: Vec<String>,
}

#[derive(Args, Debug)]
pub struct Run {
    /// The command to run and its arguments.
    ///
    /// All arguments after the `run` keyword or the first `--` option will be passed run unmodified.
    #[arg(trailing_var_arg = true)]
    #[arg(allow_hyphen_values = true)]
    #[arg(global = true)]
    command: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Write a secret to the keystore
    Set(Set),
    /// Read a secret from the keystore
    Get(Get),
    /// Read a set of secrets from the keystore and print `export ENV_NAME=secret_value` lines to stdout
    Env(Env),
    /// Run a command and pass the environment of the sub process with all secrets of the namespace
    Run(Run),
    /// Export all secrets in the namespace as `env-secrets set` commands
    Export,
}

fn main() {
    if let Err(e) = app::run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

impl App {
    pub fn namespace(&self) -> anyhow::Result<String> {
        Ok(match self.namespace {
            Some(ref namespace) => namespace.to_string(),
            None => std::env::current_dir()?
                .file_name()
                .ok_or(anyhow::anyhow!("Unable to get current directory"))?
                .to_string_lossy()
                .to_string(),
        })
    }
}

#[cfg(target_os = "macos")]
mod app {
    use std::{collections::HashMap, env, process::Stdio};

    use clap::Parser;
    use rpassword::prompt_password;

    use crate::{validate_keys, App, Cmd};

    pub fn run() -> anyhow::Result<()> {
        use security_framework::os::macos::keychain;

        let app = App::parse();
        let namespace = app.namespace()?;

        let exe = env::current_exe()?;
        let exe = exe
            .file_name()
            .ok_or(anyhow::anyhow!("Unable to get executable name"))?;
        let exe = exe.to_string_lossy();

        let chain = keychain::SecKeychain::default()?;
        let kc = chain.find_generic_password(&exe, &namespace);

        // MacOS keyring API is inconvenient for this tool, so all env secrets
        // for a namespace are stored as a single keychain entry.
        let mut kc = match kc {
            Ok((secret, _)) => serde_json::from_slice::<HashMap<String, String>>(secret.as_ref())?,
            // Entry not found
            Err(e) if e.code() == -25300 => HashMap::new(),
            Err(e) => {
                return Err(e.into());
            }
        };

        match &app.cmd {
            Cmd::Set(set) => {
                validate_keys(&[set.key.as_str()])?;

                let secret = match set.value.clone() {
                    Some(value) => value,
                    None => prompt_password("Secret: ")?,
                };

                kc.insert(set.key.clone(), secret);

                let secrets = serde_json::to_vec(&kc)?;
                chain.set_generic_password(&exe, &namespace, &secrets)?;
            }
            Cmd::Get(get) => {
                validate_keys(&[get.key.as_str()])?;

                let secret = kc
                    .get(get.key.as_str())
                    .ok_or(anyhow::anyhow!("Secret not found"))?;

                println!("{secret}");
            }
            Cmd::Env(env) => {
                validate_keys(&env.keys)?;

                for (key, secret) in &kc {
                    if env.keys.is_empty() || env.keys.contains(key) {
                        let secret = secret.replace('\'', "'\''");
                        println!("export {key}='{secret}'");
                    }
                }
            }
            Cmd::Run(run) => {
                let command = run
                    .command
                    .first()
                    .ok_or(anyhow::anyhow!("No command provided"))?;

                let mut command = std::process::Command::new(command);
                command
                    .args(&run.command[1..])
                    .envs(kc)
                    .stdout(Stdio::inherit())
                    .stdout(Stdio::inherit());

                std::process::exit(command.spawn()?.wait()?.code().unwrap_or(1))
            }
            Cmd::Export => {
                for (key, secret) in &kc {
                    let secret = secret.replace('\'', "'\''");
                    let namespace = namespace.replace('\'', "'\''");
                    println!("{exe} '{namespace}' set \"{key}\" -v '{secret}'");
                }
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod app {
    use std::{collections::HashMap, env, process::Stdio};

    use anyhow::Context;
    use clap::Parser;
    use rpassword::prompt_password;
    use secret_service::blocking::{Item, SecretService};

    use crate::{validate_keys, App, Cmd};

    pub fn run() -> anyhow::Result<()> {
        let app = App::parse();
        let namespace = app.namespace()?;

        let ss = SecretService::connect(secret_service::EncryptionType::Dh)?;
        let collection = ss.get_default_collection()?;

        match &app.cmd {
            Cmd::Set(set) => {
                validate_keys(&[set.key.as_str()])?;

                let secret = match set.value.clone() {
                    Some(value) => value,
                    None => prompt_password("Secret: ")?,
                };

                collection.create_item(
                    &format!("env-secrets/{namespace}/{key}", key = &set.key),
                    HashMap::from([
                        ("app", "env-secrets"),
                        ("namespace", &namespace),
                        ("env", &set.key),
                    ]),
                    secret.as_bytes(),
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

                let secrets = get_secrets(&ss, &namespace, &|key: &String| {
                    env.keys.is_empty() || env.keys.contains(key)
                })?;

                for (env, secret) in secrets {
                    let secret = secret.replace('\'', "'\''");

                    println!("export {env}='{secret}'");
                }
            }
            Cmd::Run(run) => {
                let command = run
                    .command
                    .first()
                    .ok_or(anyhow::anyhow!("No command provided"))?;

                let secrets = get_secrets(&ss, &namespace, &|_| true)?;

                let mut command = std::process::Command::new(command);
                command
                    .args(&run.command[1..])
                    .envs(secrets)
                    .stdout(Stdio::inherit())
                    .stdout(Stdio::inherit());

                std::process::exit(command.spawn()?.wait()?.code().unwrap_or(1))
            }
            Cmd::Export => {
                let exe = env::current_exe()?;
                let exe = exe
                    .file_name()
                    .ok_or(anyhow::anyhow!("Unable to get executable name"))?;
                let exe = exe.to_string_lossy();

                let secrets = get_secrets(&ss, &namespace, &|_| true)?;

                for (env, secret) in &secrets {
                    let namespace = namespace.replace('\'', "'\''");
                    let secret = secret.replace('\'', "'\''");

                    println!("{exe} '{namespace}' set {env} -v '{secret}'");
                }
            }
        }

        Ok(())
    }

    fn get_secrets(
        ss: &SecretService<'_>,
        namespace: &str,
        filter: &impl Fn(&String) -> bool,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let found = ss.search_items(HashMap::from([
            ("app", "env-secrets"),
            ("namespace", namespace),
        ]))?;

        let mut items = vec![];
        collect_items(&mut items, found.locked, filter, true)?;
        collect_items(&mut items, found.unlocked, filter, false)?;

        let locked = items
            .iter()
            .filter(|(locked, _, _)| *locked)
            .map(|(_, _, item)| item)
            .collect::<Vec<_>>();

        if !locked.is_empty() {
            ss.unlock_all(&locked)?;
        }

        let items = items
            .into_iter()
            .map(|(_, key, item)| {
                item.get_secret()
                    .with_context(|| format!("Unable to get `{key}` secret."))
                    .and_then(|s| {
                        String::from_utf8(s)
                            .with_context(|| format!("Secret `{key}` is not a utf-8 string."))
                    })
                    .map(|secret| (key, secret))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(items)
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
