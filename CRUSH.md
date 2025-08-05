
# Crush.md

This file provides conventions and commands for working with the codebase.

## Commands

- **Build**: `cargo build`
- **Run**: `cargo run --bin nabla`
- **Test**: `cargo test`
- **Test a single file**: `cargo test --test <test_name>` (e.g., `cargo test --test cve_tests`)
- **Lint**: `cargo check`
- **Pre-commit hooks**: `pre-commit run --all-files`

## Code Style

- **Formatting**: Handled by `pre-commit` hooks. Use `cargo fmt` for Rust files.
- **Imports**: Group imports by `std`, external crates, and internal modules.
- **Types**: Use specific types where possible. Use `anyhow::Result` for functions that can return errors.
- **Naming**: Follow Rust conventions (e.g., `snake_case` for variables and functions, `PascalCase` for types).
- **Error Handling**: Use `thiserror` to create custom error types. Propagate errors with the `?` operator.
- **Dependencies**: Add new dependencies to `Cargo.toml`.
- **Secrets**: Do not commit secrets. Use environment variables or a secrets manager.
- **Vulnerabilities**: Run `cargo audit` to check for vulnerabilities.
