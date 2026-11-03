# river

Cross-platform sandbox for running untrusted executables with resource limits,
as a Python extension implemented in Rust.

```shell
uv tool install maturin
uv run maturin develop
uv run ./examples/example.py
```

## Documentation

- [DESIGN.md](DESIGN.md) — frozen API contract and the unified cross-platform
  model (private cwd + read-only runtimes + copy_in + env)
- [docs/windows-backend.md](docs/windows-backend.md) — Windows backend
  technical design (AppContainer + Job Object + mitigation policies) and the
  staged implementation plan
