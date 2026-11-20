package plan_test

import rego.v1

import data.fixtures
import data.plan

planned(g, interfaces, presented) := p if {
	p := plan.result with input as {"graph": g, "interfaces": interfaces, "presented": presented}
}

plan_of(presented) := planned(fixtures.graph, fixtures.interfaces, presented)

full_order := ["institutional_irb_approval", "project_membership", "irb_clearance", "ethics_approval_required"]

clearance(issuer, trusted) := data.fixtures.view("IRBClearanceCredential", 7, issuer, trusted)

shortcut := [
	data.fixtures.view("IntendedDataUseCredential", 5, "did:example:dac", true),
	data.fixtures.view("publicKeyCredential", 6, "did:example:platform", true),
	clearance("did:example:office", true),
]

test_the_full_chain_runs_every_node if {
	p := plan_of({"User": fixtures.chain})
	p.order == full_order
	p.missing == []
	p.bindings.irb_clearance.membership == {"from": "node", "node": "project_membership"}
	p.bindings.irb_clearance.affiliation == {"from": "presented", "indices": [4]}
	p.parameters.channel_key == [6]
}

test_a_trusted_shortcut_skips_the_nodes_above_it if {
	p := plan_of({"User": shortcut})
	p.order == ["ethics_approval_required"]
	p.bindings.ethics_approval_required.clearance == {"from": "presented", "indices": [7]}
	p.missing == []
}

test_an_untrusted_shortcut_is_not_taken if {
	presented := array.concat(fixtures.chain, [clearance("did:example:office", false)])
	p := plan_of({"User": presented})
	p.order == full_order
	p.bindings.ethics_approval_required.clearance == {"from": "node", "node": "irb_clearance"}
}

test_the_graph_list_narrows_the_issuers if {
	g := data.fixtures.set2(fixtures.graph, "trusted_issuers", "IRBClearanceCredential", ["did:example:office"])
	elsewhere := [shortcut[0], shortcut[1], clearance("did:example:other", true)]
	planned(g, fixtures.interfaces, {"User": elsewhere}).order == full_order
	planned(g, fixtures.interfaces, {"User": shortcut}).order == ["ethics_approval_required"]
}

test_a_missing_key_is_named if {
	without_key := [c | some c in fixtures.chain; c.type != "publicKeyCredential"]
	p := plan_of({"User": without_key})
	p.missing == [{"parameter": "channel_key", "type": "publicKeyCredential", "role": "User"}]
	p.parameters.channel_key == []
}

test_a_parameter_takes_only_trusted_credentials if {
	untrusted := [c | some c in fixtures.chain; c.type != "publicKeyCredential"]
	key := data.fixtures.view("publicKeyCredential", 6, "did:example:platform", false)
	plan_of({"User": array.concat(untrusted, [key])}).missing == [{"parameter": "channel_key", "type": "publicKeyCredential", "role": "User"}]
	g := data.fixtures.set2(fixtures.graph, "trusted_issuers", "publicKeyCredential", ["did:example:elsewhere"])
	planned(g, fixtures.interfaces, {"User": fixtures.chain}).parameters.channel_key == []
}

test_a_parameter_takes_every_candidate if {
	second := data.fixtures.view("publicKeyCredential", 7, "did:example:platform", true)
	plan_of({"User": array.concat(fixtures.chain, [second])}).parameters.channel_key == [6, 7]
}

test_only_the_inputs_role_is_read if {
	p := plan_of({"Script": fixtures.chain})
	count(p.missing) == 7
}

test_a_supplied_key_input_takes_untrusted_credentials if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "ethics_approval_required", "inputs", "use", "supplied_key", true)
	g := data.fixtures.del2(fixtures.graph, "trusted_issuers", "IntendedDataUseCredential")
	presented := [c | some c in fixtures.chain; c.type != "IntendedDataUseCredential"]
	self_signed := data.fixtures.view("IntendedDataUseCredential", 5, "did:example:user", false)
	p := planned(g, interfaces, {"User": array.concat(presented, [self_signed])})
	p.bindings.ethics_approval_required.use == {"from": "presented", "indices": [5]}
	p.missing == []
}

test_every_required_node_runs if {
	interfaces := object.union(fixtures.interfaces, {"geo": {
		"output": "DataUseConditionCredential",
		"inputs": {"location": {"type": "LocationCredential", "role": "User"}},
		"policy_data_schema": {},
	}})
	with_geo := data.fixtures.set2(fixtures.graph, "nodes", "geo", {"component": "geo", "inputs": {"location": fixtures.presented}, "policy_data": {}})
	both := data.fixtures.set2(with_geo, "capability", "requires", ["ethics_approval_required", "geo"])
	g := data.fixtures.set2(both, "trusted_issuers", "LocationCredential", [])
	p := planned(g, interfaces, {"User": shortcut})
	p.order == ["ethics_approval_required", "geo"]
	p.missing == [{"node": "geo", "input": "location", "type": "LocationCredential", "role": "User"}]
}
