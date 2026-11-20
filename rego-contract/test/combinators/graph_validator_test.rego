package validate_test

import rego.v1

import data.fixtures
import data.validate

problems(g, interfaces) := found if {
	found := validate.result with input as {"graph": g, "interfaces": interfaces}
}

problems_of(g) := problems(g, fixtures.interfaces)

has(found, prefix) if {
	some p in found
	startswith(p, prefix)
}

with_input(n, name, source) := data.fixtures.set4(fixtures.graph, "nodes", n, "inputs", name, source)

with_capability(key, value) := data.fixtures.set2(fixtures.graph, "capability", key, value)

test_the_irb_graph_is_valid if {
	problems_of(fixtures.graph) == []
}

test_unknown_component if {
	g := data.fixtures.set3(fixtures.graph, "nodes", "irb_clearance", "component", "nope")
	has(problems_of(g), "node irb_clearance uses unknown component nope")
}

test_unknown_node if {
	found := problems_of(with_input("irb_clearance", "approval", data.fixtures.from_node("nope", false)))
	has(found, "node irb_clearance input approval reads unknown node nope")
}

test_unbound_input if {
	g := data.fixtures.del4(fixtures.graph, "nodes", "ethics_approval_required", "inputs", "use")
	has(problems_of(g), "node ethics_approval_required binds [\"clearance\"], component ethics_approval_required has [\"clearance\", \"use\"]")
}

test_extra_input if {
	g := data.fixtures.set4(fixtures.graph, "nodes", "ethics_approval_required", "inputs", "extra", fixtures.presented)
	has(problems_of(g), "node ethics_approval_required binds")
}

test_a_source_the_input_does_not_allow if {
	has(problems_of(with_input("ethics_approval_required", "use", {"from": "credential"})), "node ethics_approval_required input use: a source is")
	has(problems_of(with_input("ethics_approval_required", "clearance", {"from": "node", "node": "irb_clearance"})), "node ethics_approval_required input clearance: a source is")
	listed := [data.fixtures.from_node("irb_clearance", true)]
	has(problems_of(with_input("ethics_approval_required", "clearance", listed)), "node ethics_approval_required input clearance: a source is")
}

test_credential_type_mismatch if {
	found := problems_of(with_input("ethics_approval_required", "clearance", data.fixtures.from_node("project_membership", false)))
	has(found, "node ethics_approval_required input clearance wants IRBClearanceCredential, node project_membership outputs ProjectMembershipCredential")
}

test_cycle if {
	g := data.fixtures.set4(fixtures.graph, "nodes", "project_membership", "inputs", "team", data.fixtures.from_node("irb_clearance", false))
	found := problems_of(g)
	has(found, "node irb_clearance is in a cycle")
	has(found, "node project_membership is in a cycle")
}

test_node_that_leads_to_no_required_node if {
	g := data.fixtures.set2(fixtures.graph, "nodes", "spare", fixtures.graph.nodes.project_membership)
	has(problems_of(g), "node spare does not lead to the capability")
}

test_no_component_outputs_a_capability if {
	interfaces := data.fixtures.set2(fixtures.interfaces, "ethics_approval_required", "output", "Capability")
	has(problems(fixtures.graph, interfaces), "component ethics_approval_required: no component outputs a Capability")
}

test_the_capability_requires_nodes if {
	has(problems_of(with_capability("requires", ["nope"])), "the capability requires nope, which is not a node")
	has(problems_of(with_capability("requires", [])), "the capability requires a list of at least one node")
	has(problems_of(with_capability("requires", "ethics_approval_required")), "the capability requires a list of at least one node")
	twice := ["ethics_approval_required", "ethics_approval_required"]
	has(problems_of(with_capability("requires", twice)), "the capability requires each node once")
}

test_the_capability_shape if {
	has(problems_of(with_capability("extra", 1)), "the capability has exactly operation, requires and parameters")
	has(problems_of(with_capability("operation", "")), "the capability's operation must be a non-empty string")
	has(problems_of(with_capability("parameters", [])), "the capability's parameters must be an object")
	no_claim := {"channel_key": {"type": "publicKeyCredential", "role": "User"}}
	has(problems_of(with_capability("parameters", no_claim)), "capability parameter channel_key: a parameter is {type, role, claim}")
	no_capability := object.remove(fixtures.graph, ["capability"])
	has(problems_of(no_capability), "the graph has exactly")
}

test_trusted_issuers_list_exactly_the_presented_types if {
	missing := data.fixtures.del2(fixtures.graph, "trusted_issuers", "IRBClearanceCredential")
	has(problems_of(missing), "trusted_issuers lists")
	no_key := data.fixtures.del2(fixtures.graph, "trusted_issuers", "publicKeyCredential")
	has(problems_of(no_key), "trusted_issuers lists")
	extra := data.fixtures.set2(fixtures.graph, "trusted_issuers", "DataUseConditionCredential", [])
	has(problems_of(extra), "trusted_issuers lists")
	bad := data.fixtures.set2(fixtures.graph, "trusted_issuers", "TeamCredential", [""])
	has(problems_of(bad), "trusted_issuers of TeamCredential must be a list of DIDs")
}

test_two_required_nodes_are_valid if {
	interfaces := object.union(fixtures.interfaces, {"geo": {
		"output": "DataUseConditionCredential",
		"inputs": {"location": {"type": "LocationCredential", "role": "User"}},
		"policy_data_schema": {},
	}})
	with_geo := data.fixtures.set2(fixtures.graph, "nodes", "geo", {"component": "geo", "inputs": {"location": fixtures.presented}, "policy_data": {}})
	both := data.fixtures.set2(with_geo, "capability", "requires", ["ethics_approval_required", "geo"])
	g := data.fixtures.set2(both, "trusted_issuers", "LocationCredential", [])
	problems(g, interfaces) == []
}

test_a_supplied_key_input_must_be_presented if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "irb_clearance", "inputs", "membership", "supplied_key", true)
	found := problems(fixtures.graph, interfaces)
	has(found, "node irb_clearance input membership: an input the component checks against a key it supplies must be presented")
}

test_a_supplied_key_type_takes_no_trusted_issuers if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "ethics_approval_required", "inputs", "use", "supplied_key", true)
	found := problems(fixtures.graph, interfaces)
	has(found, "trusted_issuers lists")
	g := data.fixtures.del2(fixtures.graph, "trusted_issuers", "IntendedDataUseCredential")
	problems(g, interfaces) == []
}

test_interfaces_are_checked if {
	no_role := data.fixtures.del4(fixtures.interfaces, "ethics_approval_required", "inputs", "use", "role")
	has(problems(fixtures.graph, no_role), "component ethics_approval_required input use: an input is")
	not_supplied := data.fixtures.set4(fixtures.interfaces, "ethics_approval_required", "inputs", "use", "supplied_key", false)
	has(problems(fixtures.graph, not_supplied), "component ethics_approval_required input use: an input is")
	extra := data.fixtures.set2(fixtures.interfaces, "ethics_approval_required", "extra", 1)
	has(problems(fixtures.graph, extra), "component ethics_approval_required: an interface has exactly")
	unused := object.union(fixtures.interfaces, {"spare": fixtures.interfaces.project_membership})
	has(problems(fixtures.graph, unused), "component spare is not used by any node")
}

test_the_graph_shape if {
	has(problems_of(object.union(fixtures.graph, {"version": 2})), "version must be 3")
	has(problems_of(object.union(fixtures.graph, {"name": ""})), "name must be a non-empty string")
	has(problems_of(object.union(fixtures.graph, {"extra": 1})), "the graph has exactly")
	no_data := data.fixtures.del3(fixtures.graph, "nodes", "ethics_approval_required", "policy_data")
	has(problems_of(no_data), "node ethics_approval_required has exactly component, inputs and policy_data")
}

test_ids_names_roles_and_types_are_names if {
	g := data.fixtures.set2(fixtures.graph, "nodes", "a.b", fixtures.graph.nodes.project_membership)
	has(problems_of(g), "a.b is not a name")
	interfaces := data.fixtures.set4(fixtures.interfaces, "ethics_approval_required", "inputs", "use", "role", "User role")
	has(problems(fixtures.graph, interfaces), "User role is not a name")
	dotted := {"channel_key": {"type": "publicKeyCredential", "role": "User", "claim": "key.pem"}}
	has(problems_of(with_capability("parameters", dotted)), "key.pem is not a name")
}
