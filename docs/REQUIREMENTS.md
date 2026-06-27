# Sopsy — Build Requirements

These are the acceptance requirements for completing `sopsy`. The functional spec
lives in [AGENT.md](../AGENT.md); this file captures the *delivery* requirements
agreed with the maintainer. Treat both as the definition of done.

## Scope

Implement **all** features and commands described in `AGENT.md`:

- `sopsy init` — bootstrap an encrypted repo (verify tools, generate Secure Enclave
  identity, print recipient, create `.sops.yaml`, `.env.example`, encrypt
  `.env.encrypted`, update `.gitignore`, create `.sopsy.yml`, run doctor).
- `sopsy doctor` — health checks (macOS/Apple Silicon/Secure Enclave/Touch ID,
  `sops`/`age-plugin-se`/`git`, `.sops.yaml`, repo health, break-glass warning).
- `sopsy edit <file>` — `EDITOR=… sops <file>` wrapper with nicer errors; forwards
  trailing `-- <sops args>`.
- `sopsy recipient add [name]` / `remove [name]` / `list` — mutate `.sops.yaml`
  recipients, then run `sops updatekeys -r .`.
- `sopsy check` — CI gate (exit 0/1): `.env` not committed and is ignored,
  `.sops.yaml` valid, every encrypted file matches a creation rule, no plaintext
  secrets in tracked files, all encrypted files parse, break-glass recipient exists.

Out of scope for v1 (do NOT build): Linux, TPM, YubiKey, KMS, 1Password/Vault
integration, native Rust SOPS, Ratatui.

## Quality bar

1. **Tests with > 95% coverage.** Measure coverage (e.g. `cargo llvm-cov`).
2. **Test on real files** — real temp git repos, real `sops`/`age`/`age-plugin-se`
   where available; mock/fake binaries only where Secure Enclave hardware is required.
3. **GitHub Actions CI** that **fails** the build if tests, `cargo fmt --check`, or
   `cargo clippy -D warnings` fail.
4. **Idiomatic, best-practice Rust** throughout — for both library code and tests.
   Edition 2024 idioms, no `unwrap()`/`panic!` on recoverable paths (use `Result` +
   `anyhow`/`thiserror`), `clippy -D warnings` clean, small focused modules, doc
   comments on public items, table-driven/property tests where they fit.
5. **Dependencies must be healthy.** Only pull in crates that are actively maintained
   (recent commits), widely adopted (large community, many GitHub stars), and from
   reputable maintainers. Prefer the de-facto standard crate for each job; avoid
   abandoned, single-author-no-activity, or low-star libraries. Justify any
   non-obvious dependency choice in the commit message.

## UX requirements

- Terminal UI must be **colorful, playful, and very easy to use**. Use color freely,
  including animated lines that change color where it adds delight.
- **Interactive mode**: prompt the user with questions and multi-selects (via
  `inquire`); persist answers to `.sopsy.yml`.
- **Non-interactive mode**: everything settable via command-line flags so the tool is
  scriptable / CI-friendly. Interactive prompting must be suppressible.

## Documentation style

- Use **Mermaid diagrams** in markdown wherever they aid understanding (architecture,
  command flows, the encrypt/decrypt data flow, recipient/key lifecycle, CI gating).
- Use **GitHub admonitions** (`> [!NOTE]`, `> [!TIP]`, `> [!IMPORTANT]`,
  `> [!WARNING]`, `> [!CAUTION]`) throughout `README.md` and everything under `docs/`.
- End-to-end tests must cover the **dotenv (`.env`) secret format**, not only YAML/JSON
  — sops supports `dotenv` as an input/output type and it's the primary use case here.

## Process requirements

- Architecture roughly per `AGENT.md` layout (`src/cli.rs`, `src/commands/`,
  `src/sops/`, `src/enclave/`, `src/git/`, `src/doctor/`, `tests/`).
- **Single pull request**; keep pushing commits to it until all functionality is done.
- Atomic commits (one logical change each), imperative subject ≤ 50 chars.
- **Document `README.md` at the end** once features are complete.

## Definition of done

- [ ] All commands above implemented (interactive + non-interactive).
- [ ] > 95% test coverage, tests exercise real files.
- [ ] CI workflow green, and red when tests/fmt/clippy fail.
- [ ] Colorful/playful UX with interactive multi-selects.
- [ ] README documented.
- [ ] Single PR with iterative commits, all merged-ready.
