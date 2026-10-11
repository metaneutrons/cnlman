# Contributing to cnlman

## Getting Started

```bash
git clone https://github.com/metaneutrons/cnlman.git
cd cnlman
brew install lefthook gitleaks
lefthook install
cargo nextest run --workspace --all-features --locked
```

Rust is selected from `rust-toolchain.toml`.

## Branches and Commits

Create a short-lived branch from `main`. Use `feat/`, `fix/`, `docs/`,
`refactor/`, or `chore/` followed by a concise kebab-case description.

All commit messages and pull-request titles follow
[Conventional Commits](https://www.conventionalcommits.org/) and are written in
English. Keep the subject at or below 100 characters. A squash merge uses the
pull-request title as the commit subject and its body as the commit body. One
pull request carries changes of one kind.

## Engineering Guidelines

- No unsafe code: `unsafe_code = "forbid"` is enforced workspace-wide.
- stdout is a contract: one JSON object per package and line, nothing else.
  Diagnostics go to stderr. Changing the JSON fields or the exit codes is a
  breaking change.
- Tests use synthetic packages encrypted with `crypto::encrypt`, never real
  links or captured pages.
- Every new check needs a counter-probe: a test that feeds it bad input and
  expects the rejection.

Run the principal checks used by CI before opening a pull request:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked
cargo deny check
```

If `lefthook run pre-push` is too slow on your machine, run the commands above
instead of reaching for `--no-verify`; CI runs all of them anyway.

## Planning

Substantial work is planned in [`docs/plans/`](docs/plans/) with an epic and
milestone issues. The plan carries the requirements and acceptance criteria;
the issues carry execution state and evidence.

## License

By contributing, you agree that your contributions will be licensed under
GPL-3.0-or-later.
