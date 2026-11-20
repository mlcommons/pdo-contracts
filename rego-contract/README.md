# Rego contract family

Contracts that evaluate Rego modules (with [regorus](https://github.com/microsoft/regorus))
over verifiable presentations, and sign what the modules decide.

| Contract | Output |
|----------|--------|
| `rego_policy_agent` | a `policy_decision` credential, when its policy allows |
| `rego_token` | capabilities for the guardian that trusts it, from a policy agent's `policy_decision` |
| `rego_evaluator` | the output of any Rego source over any input; stateless |

A `rego_policy_agent` is an asset's policy. It issues `policy_decision` credentials
naming one guardian operation, `{name, parameters}`, which the asset's `rego_token`
turns into a capability.

Its policy -- a graph of Rego components that pass credentials to each other -- is
set once, by `set_rego_policy`, and never changes, so accepting a policy agent means
accepting one auditable policy, which anyone can read with `get_rego_policy`. Its
trusted issuers (`register_trusted_issuer`, `unregister_trusted_issuer`,
`list_trusted_issuers`, the identity family's `policy_agent`'s) and each node's
policy data (`set_policy_data`, `get_policy_data`) stay its owner's to manage. It has
no `sign` method: the only credentials its keys sign are the decisions its policy
allowed.

## Policies

Each component reads credentials and outputs credentials, and the root issues the
capability. A trusted validator checks the graph when it is set, and a trusted planner
decides per request which components run and whether a presented credential stands
in for a component's output. `get_requirements` lists the bundles of credentials that
satisfy the policy. [docs/policy_graph.md](docs/policy_graph.md) is the spec, with the
methods, the `rego_policy_agent` commands, the limits and the denial reasons.

## Tests

- `test/script_test.sh`: the CLI flow, through a guardian. CTest runs it as
  `system-rego-script` (`test/README.md`).
- `test/python/`: the Python API against a ledger -- `stateless_test.py`, the same
  flow through the token and a guardian, and `policy_graph_test.py`, which decides a
  graph's vectors on-chain (`test/python/README.md`).
- `test/graph_test.sh`: the graph combinators' tests, on OPA and on regorus, without a
  ledger. It needs `opa` and python3 with the regorus bindings (`test/README.md` says how
  to build them), and is not part of `make test`.
