# Policy graphs

A `rego_policy_agent`'s policy is a graph of Rego components that pass credentials to each
other, set once by `set_rego_policy`. The root component issues the capability, and the
agent signs it as a `policy_decision`. This page is the spec.

## Terms

| Term | Is |
| --- | --- |
| credential | A presented credential comes from a wallet, signed by an issuer, and a component reads it as `{type, issuer, subject, claims, evidence}`, its `evidence` being its own index. A produced credential is a component's output, `{type, subject, claims, evidence}` with no issuer; its `evidence` lists the indices of the presented credentials it rests on. |
| component | a Rego module, `package pf.components.<id>`, with a static `interface` rule and an evaluated `output` rule |
| node | a component instance in one graph: `{component, inputs, policy_data}` |
| source | where an input's credentials come from: `presented`, or `node` (the output of another node), which may also `accept_presented` |
| capability | what the root outputs: `{type: "Capability", subject, claims: {operation: {name, parameters}}}` |

## The graph

```json
{
  "version": 2,
  "name": "Membership download",
  "root": "download",
  "nodes": {
    "member": {"component": "member",
               "inputs": {"membership": {"from": "presented"}},
               "policy_data": {"allowedInstitutions": ["Intel"]}},
    "download": {"component": "download",
                 "inputs": {"key": {"from": "presented"},
                            "grant": {"from": "node", "node": "member", "accept_presented": true}},
                 "policy_data": {}}
  },
  "trusted_issuers": {"membership": [], "membership_grant": [], "public_key": []}
}
```

- Every input of a node's component is bound, to one source or to a list of sources.
- A `node` source takes the output of that node, whose output type must be the input's type.
  With `accept_presented: true` it takes every usable presented credential of the type and role
  instead (trusted, and from a listed issuer when the type's list is not empty), when there is
  at least one; the node it names then does not run, unless another input of an active node
  reads it.
- A list of sources reads at least two distinct nodes, each with `accept_presented: false`.
  The input takes all their outputs, and is empty unless every one of them produced at least
  one credential. Several cards on one dataset feed their grants to one root this way.
- `trusted_issuers` has exactly one key for each type an input takes from the registry -- an
  input bound to `presented`, or to a node with `accept_presented: true` -- leaving out the
  types of `supplied_key` inputs: no more keys, no fewer. Each value lists the issuer DIDs the
  graph accepts for that type; an empty list leaves the choice to the contract's registry
  (`register_trusted_issuer`).
- Node ids, component ids, input names, roles and credential types are made of letters, digits
  and `_`.
- There is no cycle, every node leads to the root, only the root outputs a `Capability`, no
  input takes one, and every component sent with the graph is used by a node.

The validator combinator (`src/rego/common/graph_validator.rego`) checks all of this when
the graph is set.

## Components

```rego
package pf.components.member

import rego.v1

interface := {
	"output": "membership_grant",
	"inputs": {"membership": {"type": "membership", "role": "applicant"}},
	"policy_data_schema": {"type": "object", "required": ["allowedInstitutions"]},
}

output := [grant |
	some membership in input.inputs.membership
	membership.claims.institution in input.policy_data.allowedInstitutions
	grant := {"type": "membership_grant", "subject": membership.subject, "claims": {}, "evidence": membership.evidence}
]
```

- `interface` is evaluated with no input. Each input names its credential type and the role
  whose presentation carries it. An input marked `"supplied_key": true` takes credentials the
  component checks itself, against a key it supplies (a credential signed by the requester's
  own wallet, for instance); it must be presented. `policy_data_schema` is a JSON Schema for
  the node's policy data, for the forms that edit it; the contract does not read it.
- `output` is evaluated over `{inputs: {<input>: [credential]}, policy_data, request}`, where
  `request` is what the requester declared to `issue_policy_credential`. It returns a list of
  at most 64 credentials of the declared output type, each with exactly the keys `{type,
  subject, claims, evidence}`: a non-empty `subject`, and `evidence` drawn from the evidence
  the node was given. A component with a `supplied_key` input also returns, on every
  credential (an empty list when there is nothing to check), `key_checks: [{index, key,
  key_type}]`: the credentials of those inputs to verify against `key` (`ec` or `rsa`). A
  capability's claims are exactly `{operation: {name, parameters}}`, with a non-empty name and
  an object of parameters.
- An output of any other shape is an error, not a denial: the call fails with "node N returned
  an ill-formed output". So a component builds its outputs; it does not pass a presented
  credential through, since that carries an `issuer`.
- regorus, which the contract embeds, refuses a comprehension in a rule head that uses body
  variables, and a comprehension nested in another; keep them in rule bodies or behind a
  function. It has no `time.*` builtins, and fails a rule whose head reads a field the value
  lacks.

## Requirements

Requirements are alternatives, each a minimal set of presented credential types by role. A
presented input needs its own type; a node input needs what its producer needs;
`accept_presented` adds the alternative of presenting the credential itself; a node needs one
alternative of each of its inputs. Alternatives that include another are dropped, and a graph
whose expansion holds more than 64 at any step is refused, even if fewer remain at the end.
`get_requirements` returns them, smallest first.

## Evaluation (`issue_policy_credential`)

1. View the presented credentials as `{type, issuer, signer, trusted, subject, claims, index,
   proof_value}`, numbered role by role. The presentations may leave out a role only some
   alternatives read, but not name a role that no alternative reads ("the presentations name a
   role the policy does not read").
2. Plan (`src/rego/common/graph_planner.rego`). A presented input takes the credentials of its
   type and role that are trusted and, when the graph lists issuers for the type, from one of
   them; a `supplied_key` input takes every credential of its type and role. The active nodes
   are those the root reaches over node sources, ordered producers first. A presented input of
   an active node with nothing to take denies, naming the node, the input, the type and the
   role.
3. Run each active node in its own engine, and check what it returns.
4. Allow only if the root returned at least one capability, and all of them carry the same
   subject and operation.
5. Verify every presented credential bound to an active node, cited or not: against the
   registry (its issuer is its signer, that signer is trusted for its type, and it is on the
   graph's list for the type when the list is not empty), or, for a `supplied_key` input, its
   issuer is its signer and it verifies against every key the node supplied for it, at least
   one. Any failure denies.
6. Sign a `policy_decision` about the capabilities' subject, whose claims are their operation.

### Denials and errors

A denial fails `issue_policy_credential` with "policy evaluation denied, " and one of:

| Reason | When |
| --- | --- |
| `node N input I needs a T presented in role R` | step 2: the first missing input |
| `the root issued no capability` | step 4: the root returned nothing |
| `the capabilities disagree` | step 4: the root's capabilities differ in subject or operation |
| `credential verification failed` | step 5 |

These are errors, not denials, and say the policy or the call is wrong: "unexpected error,
node N returned an ill-formed output", and any problem the validator finds when the policy is
set.

## Methods

| Method | Parameters | Returns | Caller |
| --- | --- | --- | --- |
| `set_rego_policy` | `{policy_graph, components: [[id, source]]}` | `true` | owner, once |
| `get_rego_policy` | none | `{policy_graph, components, sha256}` | anyone |
| `get_requirements` | none | the alternatives, `[{role: [type]}]`, smallest first | anyone |
| `set_policy_data` | `{node, policy_data}` | `true` | owner |
| `get_policy_data` | none | `{node: policy_data}` | anyone |
| `issue_policy_credential` | `{presentation: {role: <verifiable presentation>}, request}` | the signed `policy_decision` | anyone |

The trusted-issuer methods (`register_trusted_issuer`, `unregister_trusted_issuer`, owner;
`list_trusted_issuers`, anyone) are the identity family's `policy_agent`'s.

Until the policy is set, every policy method fails with "no rego policy has been set";
`set_rego_policy` refuses an agent whose policy is set, and `set_policy_data` a node the graph
does not have. `set_rego_policy` keeps each node's `policy_data` as that node's policy data
(`get_policy_data` returns them keyed by node) and stores the graph with every node's
`policy_data` emptied.

`get_rego_policy`'s `sha256` is the base64 SHA-256 of the contract's serialization of
`{policy_graph, components}`, the stored graph and the component sources. It does not cover
policy data, which the owner may change, and the `policy_decision` the agent issues does not
carry it; since the policy is set once, it identifies the composition behind every decision the
agent signs.

## Limits

At most 32 nodes, 16 components, 8 inputs per component, 64 credentials per input or output,
64 requirement alternatives and 64 KB per component source. The engine the contract embeds
has no time source, so there is no per-component time limit.

## Commands

The family's `rego_policy_agent` command (also a `pdo-shell` plugin) has:

| Command | Arguments | Does |
| --- | --- | --- |
| `set_rego_policy` | `--graph FILE --components DIR` | sends the graph and the source of each component its nodes use, read from `DIR/<id>/component.rego` |
| `get_rego_policy` | | prints `{policy_graph, components, sha256}` |
| `get_requirements` | | prints the alternatives |
| `set_policy_data` | `--node ID --data FILE` | replaces one node's policy data |
| `get_policy` | `[--file FILE]` | prints every node's policy data |
| `issue_credential` | `--presentation FILE --request JSON --issued-credential FILE` | issues the decision |
| `register`, `unregister`, `list_issuers` | | the trusted issuers, as for the identity family's policy agent |

`test/script_test.sh` runs them against a ledger.

## Tests

| Test | Needs | Runs |
| --- | --- | --- |
| `test/graph_test.sh` | `opa`, python3 with the regorus bindings (`test/README.md`) | the combinators' tests, on OPA and on regorus |
| `test/script_test.sh` | a ledger and services (`make test`, `TEST_LIST=^system-rego-script`); it starts its own guardian | the CLI flow, through the token and a guardian |
| `test/python/stateless_test.py` | a ledger, services and a guardian (see `test/python/README.md`) | the same flow through the Python API |
| `test/python/policy_graph_test.py GRAPH COMPONENTS VECTORS` | a ledger and services (see `test/python/README.md`) | a graph's vectors, decided on-chain |
