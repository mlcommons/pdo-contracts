package plan_test

import rego.v1

import data.fixtures
import data.plan

planned(g, interfaces, presented) := p if {
	p := plan.result with input as {"graph": g, "interfaces": interfaces, "presented": presented}
}

plan_of(presented) := planned(fixtures.graph, fixtures.interfaces, presented)

full_order := ["institutional_irb_approval", "project_membership", "irb_clearance", "ethics_approval_required", "grant_download"]

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
	p.bindings.irb_clearance.membership == [{"from": "node", "node": "project_membership"}]
	p.bindings.irb_clearance.affiliation == [{"from": "presented", "indices": [4]}]
	p.bindings.grant_download.key == [{"from": "presented", "indices": [6]}]
}

test_a_trusted_shortcut_skips_the_nodes_above_it if {
	p := plan_of({"User": shortcut})
	p.order == ["ethics_approval_required", "grant_download"]
	p.bindings.ethics_approval_required.clearance == [{"from": "presented", "indices": [7]}]
	p.missing == []
}

test_an_untrusted_shortcut_is_not_taken if {
	presented := array.concat(fixtures.chain, [clearance("did:example:office", false)])
	p := plan_of({"User": presented})
	p.order == full_order
	p.bindings.ethics_approval_required.clearance == [{"from": "node", "node": "irb_clearance"}]
}

test_the_graph_list_narrows_the_issuers if {
	g := data.fixtures.set2(fixtures.graph, "trusted_issuers", "IRBClearanceCredential", ["did:example:office"])
	elsewhere := [shortcut[0], shortcut[1], clearance("did:example:other", true)]
	planned(g, fixtures.interfaces, {"User": elsewhere}).order == full_order
	planned(g, fixtures.interfaces, {"User": shortcut}).order == ["ethics_approval_required", "grant_download"]
}

test_a_missing_key_is_named if {
	without_key := [c | some c in fixtures.chain; c.type != "publicKeyCredential"]
	p := plan_of({"User": without_key})
	p.missing == [{"node": "grant_download", "input": "key", "type": "publicKeyCredential", "role": "User"}]
}

test_only_the_inputs_role_is_read if {
	p := plan_of({"Script": fixtures.chain})
	count(p.missing) == 7
}

test_a_supplied_key_input_takes_untrusted_credentials if {
	interfaces := data.fixtures.set4(fixtures.interfaces, "grant_download", "inputs", "key", "supplied_key", true)
	g := data.fixtures.del2(fixtures.graph, "trusted_issuers", "publicKeyCredential")
	presented := [c | some c in fixtures.chain; c.type != "publicKeyCredential"]
	self_signed := data.fixtures.view("publicKeyCredential", 6, "did:example:user", false)
	p := planned(g, interfaces, {"User": array.concat(presented, [self_signed])})
	p.bindings.grant_download.key == [{"from": "presented", "indices": [6]}]
	p.missing == []
}

test_a_list_of_sources_runs_every_node_it_reads if {
	interfaces := object.union(fixtures.interfaces, {"geo": {
		"output": "DownloadGrantCredential",
		"inputs": {"location": {"type": "LocationCredential", "role": "User"}},
		"policy_data_schema": {},
	}})
	with_geo := data.fixtures.set2(fixtures.graph, "nodes", "geo", {"component": "geo", "inputs": {"location": fixtures.presented}, "policy_data": {}})
	both := [data.fixtures.from_node("ethics_approval_required", false), data.fixtures.from_node("geo", false)]
	with_grants := data.fixtures.set4(with_geo, "nodes", "grant_download", "inputs", "grant", both)
	g := data.fixtures.set2(with_grants, "trusted_issuers", "LocationCredential", [])
	p := planned(g, interfaces, {"User": shortcut})
	p.order == ["ethics_approval_required", "geo", "grant_download"]
	p.bindings.grant_download.grant == [{"from": "node", "node": "ethics_approval_required"}, {"from": "node", "node": "geo"}]
	p.missing == [{"node": "geo", "input": "location", "type": "LocationCredential", "role": "User"}]
}
