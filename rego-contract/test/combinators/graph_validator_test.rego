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
	g := data.fixtures.del4(fixtures.graph, "nodes", "grant_download", "inputs", "key")
	has(problems_of(g), "node grant_download binds [\"grant\"], component grant_download has [\"grant\", \"key\"]")
}

test_extra_input if {
	g := data.fixtures.set4(fixtures.graph, "nodes", "grant_download", "inputs", "extra", fixtures.presented)
	has(problems_of(g), "node grant_download binds")
}

test_a_source_the_input_does_not_allow if {
	has(problems_of(with_input("grant_download", "key", {"from": "credential"})), "node grant_download input key: a source is")
	has(problems_of(with_input("grant_download", "grant", {"from": "node", "node": "ethics_approval_required"})), "node grant_download input grant: a source is")
}

test_credential_type_mismatch if {
	found := problems_of(with_input("grant_download", "grant", data.fixtures.from_node("irb_clearance", false)))
	has(found, "node grant_download input grant wants DownloadGrantCredential, node irb_clearance outputs IRBClearanceCredential")
}

test_cycle if {
	g := data.fixtures.set4(fixtures.graph, "nodes", "project_membership", "inputs", "team", data.fixtures.from_node("irb_clearance", false))
	found := problems_of(g)
	has(found, "node irb_clearance is in a cycle")
	has(found, "node project_membership is in a cycle")
}

test_node_unreachable_from_the_root if {
	g := data.fixtures.set2(fixtures.graph, "nodes", "spare", fixtures.graph.nodes.project_membership)
	has(problems_of(g), "node spare does not lead to the root")
}

test_root_must_output_a_capability if {
	g := data.fixtures.replaced(fixtures.graph, "root", "ethics_approval_required")
	found := problems_of(g)
	has(found, "the root ethics_approval_required must output a Capability")
	has(found, "node grant_download outputs a Capability but is not the root")
}

test_root_must_be_a_node if {
	g := data.fixtures.replaced(fixtures.graph, "root", "nope")
	has(problems_of(g), "root nope is not a node")
}

test_trusted_issuers_list_exactly_the_presented_types if {
	missing := data.fixtures.del2(fixtures.graph, "trusted_issuers", "IRBClearanceCredential")
	has(problems_of(missing), "trusted_issuers lists")
	extra := data.fixtures.set2(fixtures.graph, "trusted_issuers", "DownloadGrantCredential", [])
	has(problems_of(extra), "trusted_issuers lists")
	bad := data.fixtures.set2(fixtures.graph, "trusted_issuers", "TeamCredential", [""])
	has(problems_of(bad), "trusted_issuers of TeamCredential must be a list of DIDs")
}

test_lists_of_sources if {
	two := [data.fixtures.from_node("ethics_approval_required", false), data.fixtures.from_node("ethics_approval_required", false)]
	has(problems_of(with_input("grant_download", "grant", two)), "node grant_download input grant: a list of sources reads")
	one := [data.fixtures.from_node("ethics_approval_required", false)]
	has(problems_of(with_input("grant_download", "grant", one)), "node grant_download input grant: a list of sources reads at least two")
	accepting := [fixtures.presented, data.fixtures.from_node("ethics_approval_required", false)]
	has(problems_of(with_input("grant_download", "grant", accepting)), "node grant_download input grant: a list of sources reads each node once")
}

test_a_list_of_grants_from_two_cards_is_valid if {
	interfaces := object.union(fixtures.interfaces, {"geo": {
		"output": "DownloadGrantCredential",
		"inputs": {"location": {"type": "LocationCredential", "role": "User"}},
		"policy_data_schema": {},
	}})
	with_geo := data.fixtures.set2(fixtures.graph, "nodes", "geo", {"component": "geo", "inputs": {"location": fixtures.presented}, "policy_data": {}})
	both := [data.fixtures.from_node("ethics_approval_required", false), data.fixtures.from_node("geo", false)]
	with_grants := data.fixtures.set4(with_geo, "nodes", "grant_download", "inputs", "grant", both)
	g := data.fixtures.set2(with_grants, "trusted_issuers", "LocationCredential", [])
	problems(g, interfaces) == []
}

test_a_supplied_key_input_must_be_presented if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "irb_clearance", "inputs", "membership", "supplied_key", true)
	found := problems(fixtures.graph, interfaces)
	has(found, "node irb_clearance input membership: an input the component checks against a key it supplies must be presented")
}

test_a_supplied_key_type_takes_no_trusted_issuers if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "grant_download", "inputs", "key", "supplied_key", true)
	found := problems(fixtures.graph, interfaces)
	has(found, "trusted_issuers lists")
	g := data.fixtures.del2(fixtures.graph, "trusted_issuers", "publicKeyCredential")
	problems(g, interfaces) == []
}

test_interfaces_are_checked if {
	no_role := data.fixtures.del4(fixtures.interfaces, "grant_download", "inputs", "key", "role")
	has(problems(fixtures.graph, no_role), "component grant_download input key: an input is")
	not_supplied := data.fixtures.set4(fixtures.interfaces, "grant_download", "inputs", "key", "supplied_key", false)
	has(problems(fixtures.graph, not_supplied), "component grant_download input key: an input is")
	extra := data.fixtures.set2(fixtures.interfaces, "grant_download", "extra", 1)
	has(problems(fixtures.graph, extra), "component grant_download: an interface has exactly")
	unused := object.union(fixtures.interfaces, {"spare": fixtures.interfaces.project_membership})
	has(problems(fixtures.graph, unused), "component spare is not used by any node")
}

test_the_graph_shape if {
	has(problems_of(object.union(fixtures.graph, {"version": 1})), "version must be 2")
	has(problems_of(object.union(fixtures.graph, {"name": ""})), "name must be a non-empty string")
	has(problems_of(object.union(fixtures.graph, {"extra": 1})), "the graph has exactly")
	no_data := data.fixtures.del3(fixtures.graph, "nodes", "grant_download", "policy_data")
	has(problems_of(no_data), "node grant_download has exactly component, inputs and policy_data")
}

test_ids_names_roles_and_types_are_names if {
	g := data.fixtures.set2(fixtures.graph, "nodes", "a.b", fixtures.graph.nodes.project_membership)
	has(problems_of(g), "a.b is not a name")
	interfaces := data.fixtures.set4(fixtures.interfaces, "grant_download", "inputs", "key", "role", "User role")
	has(problems(fixtures.graph, interfaces), "User role is not a name")
}
