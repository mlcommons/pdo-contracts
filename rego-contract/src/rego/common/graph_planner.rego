# REGO_GRAPH_PLANNER: the trusted planner issue_policy_credential runs over a validated policy
# graph and the presented credentials, before any component. It decides which source each
# input takes, which nodes run and in which order, which presented credentials each parameter
# of the capability may be read from, and which presented inputs have nothing to take. The
# contract embeds this source.
#   input : { "graph": <policy graph>, "interfaces": { <component id>: <interface> },
#             "presented": { <role>: [ <credential view>, ... ] } }
#   output (data.plan.result):
#           { "order": [ <node>, ... ],               # the active nodes, producers first
#             "bindings": { <node>: { <input>: <entry> } },
#             "parameters": { <parameter>: [ <index>, ... ] },
#             "missing": [ { "node", "input", "type", "role" }
#                          or { "parameter", "type", "role" }, ... ] }
#   An entry is { "from": "presented", "indices": [ <index>, ... ] } or
#   { "from": "node", "node": <node> }.
#
# Comprehensions stay in rule bodies or behind functions, and none is nested in another:
# regorus refuses both forms.

package plan

import rego.v1

policy := input.graph

nodes := policy.nodes

capability := policy.capability

spec(n, name) := input.interfaces[nodes[n].component].inputs[name]

issuer_listed(t, _) if count(policy.trusted_issuers[t]) == 0

issuer_listed(t, c) if c.issuer in policy.trusted_issuers[t]

# a presented credential an input may take: trusted by the contract for its type and, when
# the graph lists issuers for the type, from one of them; or, for an input the component
# checks against a key it supplies, any credential of the type
usable(s, _) if s.supplied_key == true

usable(s, c) if {
	not s.supplied_key
	c.trusted == true
	issuer_listed(s.type, c)
}

# the presented credentials s, an input's spec or a parameter, may take
offered(s) := [c.index |
	some c in input.presented[s.role]
	c.type == s.type
	usable(s, c)
]

candidates(n, name) := offered(spec(n, name))

# a node input that accepts presented credentials takes them when there are any, and then
# the nodes that would produce them are not needed
takes_presented(_, _, s) if s.from == "presented"

takes_presented(n, name, s) if {
	s.from == "node"
	s.accept_presented == true
	count(candidates(n, name)) > 0
}

entry(n, name, s) := {"from": "presented", "indices": candidates(n, name)} if takes_presented(n, name, s)

entry(n, name, s) := {"from": "node", "node": s.node} if not takes_presented(n, name, s)

# node -> the nodes it reads, over the entries that read a node
deps[n] := ds if {
	some n, node in nodes
	ds := {e.node | some name, s in node.inputs; e := entry(n, name, s); e.from == "node"}
}

required := {n | some n in capability.requires}

active := graph.reachable(deps, required)

# a producer's closure is a strict subset of its consumer's, so ordering by closure size
# runs producers first without recursion
sized := sort([[count(graph.reachable(deps, {n})), n] | some n in active])

order := [p[1] | some p in sized]

bindings[n] := slots if {
	some n in active
	slots := {name: entry(n, name, s) | some name, s in nodes[n].inputs}
}

parameters[p] := offered(s) if some p, s in capability.parameters

missing contains {"node": n, "input": name, "type": s.type, "role": s.role} if {
	some n in active
	some name, raw in nodes[n].inputs
	raw == {"from": "presented"}
	count(candidates(n, name)) == 0
	s := spec(n, name)
}

missing contains {"parameter": p, "type": s.type, "role": s.role} if {
	some p, s in capability.parameters
	count(offered(s)) == 0
}

result := {
	"order": order,
	"bindings": bindings,
	"parameters": parameters,
	"missing": [m | some m in missing],
}
