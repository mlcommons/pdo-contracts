# Tests

- CLI test, against a ledger:
  - Scripts: `script_test.sh` (a policy graph, through a guardian) and
    `script_test_rego.sh` (the stateless evaluator).
  - How to run:
    - Run the ledger and the services containers; `script_test.sh` starts its own guardian.
    - Copy the ledger's root cert and the services' site.toml to the correct locations.
    - Run `TEST_LIST=^system-rego-script make -C ${PDO_CONTRACTS_ROOT} test`
      (`^system-rego-rego_script` for the evaluator).

- Python test, against a ledger:
  - Folder: `python`; see `python/README.md`.

- The graph combinators, without a ledger:
  - Script: `graph_test.sh`. It runs the tests in `combinators/` of the validator and the
    planner (`../src/rego/graph_*.rego`) on OPA and on regorus.
  - Needs `opa`, and python3 with the regorus Python bindings, which are not on PyPI. Build
    them from the commit the contract pins (`../src/packages/regorus/build.sh`), with the
    contract's builtins, so that Rego which runs there also runs in the contract:

    ```bash
    cd regorus/bindings/python
    maturin build --release --no-default-features --features "regorus/opa-no-std,regorus/std"
    ```

  - How to run: `bash rego-contract/test/graph_test.sh`.
