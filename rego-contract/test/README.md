# Tests

- CLI test, against a ledger:
  - Scripts: `script_test.sh` (a flat and a graph policy, through a guardian) and
    `script_test_rego.sh` (the stateless evaluator).
  - How to run:
    - Run the ledger and the services containers, and a guardian.
    - Copy the ledger's root cert and the services' site.toml to the correct locations.
    - Run `TEST_LIST=^system-rego-script make -C ${PDO_CONTRACTS_ROOT} test`
      (`^system-rego-rego_script` for the evaluator).

- Python test, against a ledger:
  - Folder: `python`; see `python/README.md`.

- Graph mode, without a ledger:
  - Script: `graph_test.sh`. It runs the graph combinators' tests (`combinators/`) on OPA
    and on regorus, and every graph in `graphs/` through the reference implementation
    (`pdo-rego-graph eval`).
  - Needs `opa`, and python3 with the regorus bindings (built as
    `../pdo/rego/graph/engine.py` describes).
  - How to run: `bash rego-contract/test/graph_test.sh`.
