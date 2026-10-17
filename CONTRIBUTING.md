# Contributing

SeyLock helps applications reach their own servers from censored networks.
Bug reports, measurements from real networks, integrations and code are all
welcome.

## Security issues

Do not open a public issue. Report them privately as described in
[SECURITY.md](SECURITY.md).

## Reporting a problem

Open an issue with:
- the version;
- the platform;
- what you expected;
- what happened.

For a network problem, say which paths the list had, which one answered (the
`x-transport-path` response header), and what the network blocks, if you
know. Leave out anything that identifies people or networks: no Wi-Fi names,
no IP addresses of users.

## Changing the code

Before a pull request, run:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features lab-roots -- -D warnings
cargo test
cargo test --features lab-roots
```

- **A fix comes with a test** that fails without it.
- **A change to what lists may contain** goes with:
  - an update of [PROTOCOL.md](PROTOCOL.md);
  - new or changed vectors (`cargo run --example make_vectors`);
  - the same rule in `tools/verify_vectors.py`.

  CI checks that the two implementations agree on every vector.
- **A change to the C ABI** updates `include/seylock.h`, and
  `tools/check_c_abi.sh` must pass.
- **The minimum supported Rust version is 1.93.** Releases are built with
  1.93.1 (`tools/release_env.sh`), so that anyone can rebuild them byte for
  byte.
- **Keep dependencies few.** The core has 16 direct dependencies, and every
  new one is code an auditor must read and an application must ship.
- **Comments and documentation are in English.**

## Licence

SeyLock is under the [Mozilla Public License 2.0](LICENSE). By sending a
contribution you agree that it is licensed under the MPL-2.0 too. There is no
contributor licence agreement.

## How decisions are made

SeyLock has one maintainer, Yurii Arkhanhelskyi, who reviews and merges
changes and makes releases. Releases follow semantic versioning: before 1.0,
a change that breaks Rust callers raises the minor version. Every release is
listed in [CHANGELOG.md](CHANGELOG.md). Larger changes, such as new path
kinds or a new list format, start as an issue, so that their effect on
existing lists and applications is discussed before code is written.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
