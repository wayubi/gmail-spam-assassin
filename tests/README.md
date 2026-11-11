# Tests

Plain Python, no test framework required:

```sh
python3 tests/test_app.py
python3 tests/test_runner.py
python3 tests/test_idle.py
# or all three:
tests/run_all.sh
```

They use fake IMAP connections and a local fake IDLE server; no Gmail
credentials and no network access are needed. `test_app.py` binds a local
HTTP port (18099).
