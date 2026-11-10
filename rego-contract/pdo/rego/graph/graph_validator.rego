# REGO_GRAPH_VALIDATOR: the trusted check set_policy_graph runs over a policy graph and the
# interfaces of its components before anything is stored. The contract embeds this source.
#   input : { "graph": <policy graph>, "interfaces": { <component id>: <interface> } }
#   output (data.validate.result): every problem, sorted; an empty list means the graph is valid
#
# Comprehensions stay in rule bodies or behind functions, and none is nested in another:
# regorus refuses both forms.

package validate

import rego.v1

policy := input.graph

nodes := policy.nodes

interfaces := input.interfaces

presented := {"from": "presented"}

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

text(s) if {
	is_string(s)
	s != ""
}

# ids, input names, roles and types become keys and package names
identifier(s) if {
	is_string(s)
	regex.match(`^[A-Za-z0-9_]+$`, s)
}

problems contains sprintf("%v is not a name: letters, digits and _ only", [s]) if {
	some s in names
	not identifier(s)
}

names contains n if some n, _ in nodes

names contains c if some c, _ in interfaces

names contains name if {
	some iface in interfaces
	some name, _ in iface.inputs
}

# regorus fails a rule whose head reads a field the value lacks, so heads read only
# what the body has bound
names contains role if {
	some iface in interfaces
	some spec in iface.inputs
	role := spec.role
}

names contains type if {
	some iface in interfaces
	some spec in iface.inputs
	type := spec.type
}

# ---- interfaces

valid_input(spec) if {
	object.keys(spec) == {"type", "role"}
	text(spec.type)
	text(spec.role)
}

# an input whose credentials the component checks against a key it supplies (key_checks)
valid_input(spec) if {
	object.keys(spec) == {"type", "role", "supplied_key"}
	text(spec.type)
	text(spec.role)
	spec.supplied_key == true
}

problems contains sprintf("component %v: an interface has exactly output, inputs and policy_data_schema", [c]) if {
	some c, iface in interfaces
	object.keys(iface) != {"output", "inputs", "policy_data_schema"}
}

problems contains sprintf("component %v: output must be a credential type", [c]) if {
	some c, iface in interfaces
	not text(iface.output)
}

problems contains sprintf("component %v: policy_data_schema must be an object", [c]) if {
	some c, iface in interfaces
	not is_object(iface.policy_data_schema)
}

problems contains sprintf("component %v input %v: an input is {type, role}, or {type, role, supplied_key: true}", [c, name]) if {
	some c, iface in interfaces
	some name, spec in iface.inputs
	not valid_input(spec)
}

problems contains sprintf("component %v input %v: no input takes a Capability", [c, name]) if {
	some c, iface in interfaces
	some name, spec in iface.inputs
	spec.type == "Capability"
}

used contains component if {
	some node in nodes
	component := node.component
}

problems contains sprintf("component %v is not used by any node", [c]) if {
	some c, _ in interfaces
	not c in used
}

# ---- the graph and its nodes

problems contains "the graph has exactly version, name, root, nodes and trusted_issuers" if {
	object.keys(policy) != {"version", "name", "root", "nodes", "trusted_issuers"}
}

problems contains "version must be 2" if policy.version != 2

problems contains "name must be a non-empty string" if not text(policy.name)

problems contains sprintf("root %v is not a node", [policy.root]) if not nodes[policy.root]

problems contains sprintf("node %v has exactly component, inputs and policy_data", [n]) if {
	some n, node in nodes
	object.keys(node) != {"component", "inputs", "policy_data"}
}

problems contains sprintf("node %v uses unknown component %v", [n, node.component]) if {
	some n, node in nodes
	not interfaces[node.component]
}

problems contains sprintf("node %v: policy_data must be an object", [n]) if {
	some n, node in nodes
	not is_object(node.policy_data)
}

problems contains sprintf("node %v binds %v, component %v has %v", [n, sort(object.keys(node.inputs)), node.component, sort(object.keys(iface.inputs))]) if {
	some n, node in nodes
	iface := interfaces[node.component]
	object.keys(node.inputs) != object.keys(iface.inputs)
}

problems contains sprintf("the root %v must output a Capability", [policy.root]) if {
	interfaces[nodes[policy.root].component].output != "Capability"
}

problems contains sprintf("node %v outputs a Capability but is not the root", [n]) if {
	some n, node in nodes
	n != policy.root
	interfaces[node.component].output == "Capability"
}

# ---- sources

valid_source(s) if s == presented

valid_source(s) if {
	object.keys(s) == {"from", "node", "accept_presented"}
	s.from == "node"
	text(s.node)
	is_boolean(s.accept_presented)
}

problems contains sprintf("node %v input %v: a source is {from: presented} or {from: node, node, accept_presented}", [n, name]) if {
	some n, node in nodes
	some name, raw in node.inputs
	some s in as_list(raw)
	not valid_source(s)
}

# an input with several sources takes the outputs of several nodes, such as the grants of
# several cards on one dataset
problems contains sprintf("node %v input %v: a list of sources reads at least two distinct nodes", [n, name]) if {
	some n, node in nodes
	some name, raw in node.inputs
	is_array(raw)
	count({s.node | some s in raw}) < 2
}

list_source(s) if {
	valid_source(s)
	s.from == "node"
	s.accept_presented == false
}

problems contains sprintf("node %v input %v: a list of sources reads each node once, with accept_presented false", [n, name]) if {
	some n, node in nodes
	some name, raw in node.inputs
	is_array(raw)
	some s in raw
	not list_source(s)
}

problems contains sprintf("node %v input %v: a list of sources reads each node once, with accept_presented false", [n, name]) if {
	some n, node in nodes
	some name, raw in node.inputs
	is_array(raw)
	count({s.node | some s in raw}) != count(raw)
}

problems contains sprintf("node %v input %v reads unknown node %v", [n, name, s.node]) if {
	some n, node in nodes
	some name, raw in node.inputs
	some s in as_list(raw)
	s.from == "node"
	not nodes[s.node]
}

problems contains sprintf("node %v input %v wants %v, node %v outputs %v", [n, name, want, s.node, got]) if {
	some n, node in nodes
	some name, raw in node.inputs
	want := interfaces[node.component].inputs[name].type
	some s in as_list(raw)
	s.from == "node"
	got := interfaces[nodes[s.node].component].output
	got != want
}

problems contains sprintf("node %v input %v: an input the component checks against a key it supplies must be presented", [n, name]) if {
	some n, node in nodes
	some name, raw in node.inputs
	interfaces[node.component].inputs[name].supplied_key == true
	raw != presented
}

# ---- shape: no cycle, every node leads to the root

deps[n] := ds if {
	some n, node in nodes
	ds := {s.node | some _, raw in node.inputs; some s in as_list(raw); s.from == "node"}
}

problems contains sprintf("node %v is in a cycle", [n]) if {
	some n, ds in deps
	n in graph.reachable(deps, ds)
}

leads_to_root := graph.reachable(deps, {policy.root})

problems contains sprintf("node %v does not lead to the root", [n]) if {
	some n, _ in nodes
	not n in leads_to_root
}

# ---- trusted issuers: one list for each type the graph may take presented and verify
# against the registry; an empty list leaves the choice to the registry

takes_presented(raw) if raw == presented

takes_presented(raw) if raw.accept_presented == true

registry_types contains type if {
	some node in nodes
	some name, raw in node.inputs
	takes_presented(raw)
	spec := interfaces[node.component].inputs[name]
	not spec.supplied_key
	type := spec.type
}

problems contains sprintf("trusted_issuers lists %v, the graph takes %v presented", [sort(object.keys(policy.trusted_issuers)), sort(registry_types)]) if {
	object.keys(policy.trusted_issuers) != registry_types
}

valid_issuers(dids) if {
	is_array(dids)
	every d in dids {
		text(d)
	}
}

problems contains sprintf("trusted_issuers of %v must be a list of DIDs", [t]) if {
	some t, dids in policy.trusted_issuers
	not valid_issuers(dids)
}

result := sort(problems)
