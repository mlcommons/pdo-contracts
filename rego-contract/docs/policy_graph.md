# Policy graphs

A `rego_policy_agent` holds one of two kinds of policy, set once:

- **flat**, by `set_rego_policy`: subpolicies that all read the same input, combined by
  the results combinator (see the family README);
- **graph**, by `set_policy_graph`: Rego components that pass credentials to each other.
  The root component issues the capability, and the agent signs it as a
  `policy_decision`, as for a flat asset policy.

This page is the spec of graph mode. `pdo.rego.graph` is its reference implementation, in
Python, and `pdo-rego-graph` its command line.

## Terms

| Term | Is |
| --- | --- |
| credential | `{type, issuer, subject, claims, evidence}`. A presented credential comes from a wallet, signed by an issuer; its `evidence` is its own index. A produced credential is a component's output; its `evidence` lists the indices of the presented credentials it rests on. |
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
  With `accept_presented: true` it takes a trusted presented credential of the type instead,
  when there is one, and the nodes that would produce it do not run.
- A list of sources reads at least two distinct nodes, each with `accept_presented: false`.
  The input takes all their outputs, and is empty unless every one of them produced at least
  one credential. Several cards on one dataset feed their grants to one root this way.
- `trusted_issuers` lists, for each type the graph may take presented and verify against the
  registry, the issuer DIDs it accepts. An empty list leaves the choice to the contract's
  registry (`register_trusted_issuer`).
- Node ids, component ids, input names, roles and credential types are made of letters, digits
  and `_`.
- There is no cycle, every node leads to the root, and only the root outputs a `Capability`.

`docs/schemas/policy_graph.schema.json` has the shape; the validator combinator
(`pdo/rego/graph/graph_validator.rego`) is the authority.

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
  credentials of the declared output type, each `{type, subject, claims, evidence}`, whose
  evidence is drawn from the evidence it was given. A component with a `supplied_key` input
  also returns, on each credential, `key_checks: [{index, key, key_type}]`: the credentials
  of those inputs to verify against `key` (`ec` or `rsa`).
- regorus, which the contract embeds, refuses a comprehension in a rule head that uses body
  variables, and a comprehension nested in another; keep them in rule bodies or behind a
  function. It has no `time.*` builtins, and fails a rule whose head reads a field the value
  lacks.

## Requirements

Requirements are alternatives, each a minimal set of presented credential types by role. A
presented input needs its own type; a node input needs what its producer needs;
`accept_presented` adds the alternative of presenting the credential itself; a node needs one
alternative of each of its inputs. Alternatives that include another are dropped, and a graph
with more than 64 is refused. `get_requirement_alternatives` returns them smallest first, and
`get_requirements` returns the first.

## Evaluation (`issue_policy_credential`)

1. View the presented credentials as for a flat policy, `{type, issuer, signer, trusted,
   subject, claims, index}`. The presentations may leave out a role only some alternatives
   read, but not name a role the graph never reads.
2. Plan (`pdo/rego/graph/graph_planner.rego`). A presented input takes the credentials of its
   type and role that are trusted and, when the graph lists issuers for the type, from one of
   them; a `supplied_key` input takes every credential of its type and role. The active nodes
   are those the root reaches over node sources, ordered producers first. A presented input of
   an active node with nothing to take denies, naming the node, the input and the type.
3. Run each active node in its own engine, and check what it returns.
4. Allow only if the root returned at least one capability, and all of them carry the same
   subject and operation.
5. Verify every presented credential bound to an active node, cited or not: against the
   registry (its issuer is its signer, that signer is trusted for its type, and it is on the
   graph's list for the type when the list is not empty), or, for a `supplied_key` input,
   against every key the node supplied for it, at least one. Any failure denies.
6. Sign a `policy_decision` about the capabilities' subject, whose claims are their operation.

`explain_policy_decision` runs steps 1 to 4 and returns the plan, each node's output and the
verdict; it verifies nothing and signs nothing.

## Methods

| Method | Parameters | Returns | Caller |
| --- | --- | --- | --- |
| `set_policy_graph` | `{policy_graph, components: [[id, source]]}` | `true` | owner, once |
| `get_policy_graph` | none | `{policy_graph, components, sha256}` | anyone |
| `get_requirement_alternatives` | none | `{default, alternatives}`; a flat policy has one | anyone |
| `set_node_policy_data` | `{node, policy_data}` | `true` | owner |
| `explain_policy_decision` | as `issue_policy_credential` | `{plan, outputs, decision, reason}` | anyone |

`set_policy_graph` keeps each node's `policy_data` as that node's policy data
(`get_policy_data` returns them keyed by node) and stores the graph without them.
`get_policy_graph`'s `sha256` covers the graph and the components, so a decision can be tied
to the composition that made it.

## Limits

At most 32 nodes, 16 components, 8 inputs per component, 64 credentials per input or output,
64 requirement alternatives and 64 KB per component source. The engine the contract embeds
has no time source, so there is no per-component time limit.

## Reference implementation

`pdo.rego.graph` runs the contract's validator and planner and the components on the regorus
Python bindings, built from the contract's pinned commit with its builtins (see
`pdo/rego/graph/engine.py`).

```bash
pdo-rego-graph validate     --graph graph.json --components DIR
pdo-rego-graph requirements --graph graph.json --components DIR
pdo-rego-graph eval         --graph graph.json --components DIR --vectors graph_vectors.json
```

`DIR` holds `<component id>/component.rego`. The vector format is in
`pdo/rego/graph/vectors.py`; `test/graphs/download/` has a graph, its components and its
vectors.
