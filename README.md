# 🔑 env-secrets

[![MIT/Apache 2.0](https://img.shields.io/badge/license-MIT%2FApache-blue.svg)](https://github.com/nikarh/env-secrets#license)
[![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/nikarh/env-secrets/main.yaml)](https://github.com/nikarh/env-secrets/actions/workflows/main.yaml)
[![Current Release](https://img.shields.io/github/release/nikarh/env-secrets.svg)](https://github.com/nikarh/env-secrets/releases)
[![Release RSS Feed](https://img.shields.io/badge/rss-releases-ffa500?logo=rss)](https://github.com/nikarh/env-secrets/releases.atom)
[![Main Commits RSS Feed](https://img.shields.io/badge/rss-commits-ffa500?logo=rss)](https://github.com/nikarh/env-secrets/commits/main.atom)

Env-secrets is a simple CLI tool that allows setting secrets as environment variables for development without actually storing secrets in plaintext on disk.

## Motivation

Sometimes one has to work on the development of services that are configured via environment variables, and some of those environment variables are secrets, such as passwords and encryption keys. Storing secrets unencrypted on disk in `.env` files (even with full disk encryption) is generally a bad idea. This project aims to partially solve this problem by providing a way to store such env variables in the keyring ([DBUS Secret Service API] provider on Linux, or [Keychain] on Mac OS), and an interface to run your service providing these secrets via env to the subprocess.

## Usage

All secrets are grouped by a namespace. A namespace is an arbitrary string that by default is set to the name of the current working directory, and can be explicitly defined for each command.
A namespace is useful not only to group secrets by projects but also to define an environment, for instance, the namespace can be set to `my-service/prod` or `my-service/test`.

Example:

```bash
mkdir -p ~/test/project-a

# Set secrets for the namespace `project-a`
cd ~/test/project-a
env-secrets set MY_ENV_NAME1 # Will prompt to enter the password
env-secrets set MY_ENV_NAME2 -v secret_value # Will use the argument as a value
env-secrets project-a set MY_ENV_NAME3 -v secret_value # Will use the argument as a value
env-secrets project-b set MY_ENV_NAME1 -v secret_value # Will NOT overlap with with `project-a` secrets

# Write the value of a particular secret to stdout
env-secrets get MY_ENV_NAME1
env-secrets project-a get MY_ENV_NAME1

# Run a sub-process with secrets
env-secrets run env
env-secrets project-a run env

# Print secrets as lines in a form of `export NAME="value"` to stdout
env-secrets env
echo $(eval "$(env-secrets env)"; env) # Can be eval'ed by bash

# Export secrets of a namespace. Useful to import the secrets later on a different machine.
# Will print secrets as lines in a form of `env-secrets NAMESPACE set NAME -v "value"`
env-secrets export
```

## Security considerations

Does this service solve all the security concerns for services that require secrets as environment variables? Probably not. The best approach is still for the service to use a security vault directly via API.

If the Secret Service is configured in a way that requires manual interactive confirmation on any request to the secrets, this tool can prevent secret leakage by rogue dependencies (in projects that use a dependency manager that can run arbitrary code).

## Supported platforms

Currently, the only supported platforms are x86_64 or aarch64 Linux, and x86_64 or aarch64 MacOS.

## License

Except where noted (below and/or in individual files), all code in this repository is dual-licensed at your option under either:

* MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

[Keychain]: https://support.apple.com/guide/keychain-access/what-is-keychain-access-kyca1083/mac
[DBUS Secret Service API]: https://specifications.freedesktop.org/secret-service/latest/
