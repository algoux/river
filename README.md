# river

## Testing

```shell
uv sync --extra test
uv run maturin develop
uv run pytest
cargo test --lib -- --test-threads=1
```
