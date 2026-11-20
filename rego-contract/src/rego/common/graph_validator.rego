# REGO_GRAPH_VALIDATOR: the trusted check set_rego_policy runs over a policy graph and the
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

capability := policy.capability

# the capability's list of nodes and its parameters, read only when they have their shape:
# regorus fails a builtin or an iteration given a value of the wrong kind
required_list := capability.requires if is_array(capability.requires)

parameters := capability.parameters if is_object(capability.parameters)

interfaces := input.interfaces

presented := {"from": "presented"}

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

# a parameter of the capability is a key of the request and of the operation; its role,
# type and claim are keys of the presented credentials
names contains name if some name, _ in parameters

names contains role if {
	some spec in parameters
	role := spec.role
}

names contains type if {
	some spec in parameters
	type := spec.type
}

names contains claim if {
	some spec in parameters
	claim := spec.claim
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

# the graph's capability issues the capability, from what the nodes it requires produce
problems contains sprintf("component %v: no component outputs a Capability", [c]) if {
	some c, iface in interfaces
	iface.output == "Capability"
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

problems contains "the graph has exactly version, name, nodes, capability and trusted_issuers" if {
	object.keys(policy) != {"version", "name", "nodes", "capability", "trusted_issuers"}
}

problems contains "version must be 3" if policy.version != 3

problems contains "name must be a non-empty string" if not text(policy.name)

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

# ---- the capability: the operation the graph issues, the nodes that must all hold, and
# for each parameter of the operation the presented credential whose claim it is

capability_shaped if {
	is_object(capability)
	object.keys(capability) == {"operation", "requires", "parameters"}
}

problems contains "the capability has exactly operation, requires and parameters" if not capability_shaped

problems contains "the capability's operation must be a non-empty string" if not text(capability.operation)

nonempty_list(x) if {
	is_array(x)
	count(x) > 0
}

problems contains "the capability requires a list of at least one node" if not nonempty_list(capability.requires)

problems contains sprintf("the capability requires %v, which is not a node", [n]) if {
	some n in required_list
	not nodes[n]
}

problems contains "the capability requires each node once" if {
	count({n | some n in required_list}) != count(required_list)
}

valid_parameter(spec) if {
	is_object(spec)
	object.keys(spec) == {"type", "role", "claim"}
	text(spec.type)
	text(spec.role)
	text(spec.claim)
}

problems contains "the capability's parameters must be an object" if not is_object(capability.parameters)

problems contains sprintf("capability parameter %v: a parameter is {type, role, claim}", [p]) if {
	some p, spec in parameters
	not valid_parameter(spec)
}

# ---- sources

valid_source(s) if s == presented

valid_source(s) if {
	is_object(s)
	object.keys(s) == {"from", "node", "accept_presented"}
	s.from == "node"
	text(s.node)
	is_boolean(s.accept_presented)
}

problems contains sprintf("node %v input %v: a source is {from: presented} or {from: node, node, accept_presented}", [n, name]) if {
	some n, node in nodes
	some name, s in node.inputs
	not valid_source(s)
}

problems contains sprintf("node %v input %v reads unknown node %v", [n, name, s.node]) if {
	some n, node in nodes
	some name, s in node.inputs
	s.from == "node"
	not nodes[s.node]
}

problems contains sprintf("node %v input %v wants %v, node %v outputs %v", [n, name, want, s.node, got]) if {
	some n, node in nodes
	some name, s in node.inputs
	want := interfaces[node.component].inputs[name].type
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

# ---- shape: no cycle, every node leads to a node the capability requires

deps[n] := ds if {
	some n, node in nodes
	ds := {s.node | some _, s in node.inputs; s.from == "node"}
}

problems contains sprintf("node %v is in a cycle", [n]) if {
	some n, ds in deps
	n in graph.reachable(deps, ds)
}

required := {n | some n in required_list}

leads_to_capability := graph.reachable(deps, required)

problems contains sprintf("node %v does not lead to the capability", [n]) if {
	some n, _ in nodes
	not n in leads_to_capability
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

# the credential a parameter is read from is presented, and verified against the registry
registry_types contains type if {
	some spec in parameters
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
