# Fixtures for the graph combinator tests: an IRB-shaped graph of four components.

package fixtures

import rego.v1

user(t) := {"type": t, "role": "User"}

interfaces := {
	"project_membership": {
		"output": "ProjectMembershipCredential",
		"inputs": {"team": user("TeamCredential"), "ownership": user("ProjectOwnershipCredential")},
		"policy_data_schema": {},
	},
	"institutional_irb_approval": {
		"output": "InstitutionalIRBApprovalCredential",
		"inputs": {"accreditation": user("EthicsCommitteeAccreditationCredential"), "irb": user("IRBApprovalCredential")},
		"policy_data_schema": {},
	},
	"irb_clearance": {
		"output": "IRBClearanceCredential",
		"inputs": {
			"approval": user("InstitutionalIRBApprovalCredential"),
			"affiliation": user("AffiliationCredential"),
			"membership": user("ProjectMembershipCredential"),
		},
		"policy_data_schema": {},
	},
	"ethics_approval_required": {
		"output": "DataUseConditionCredential",
		"inputs": {"clearance": user("IRBClearanceCredential"), "use": user("IntendedDataUseCredential")},
		"policy_data_schema": {},
	},
}

presented := {"from": "presented"}

from_node(n, accept) := {"from": "node", "node": n, "accept_presented": accept}

graph := {
	"version": 3,
	"name": "Ethics Approval Required",
	"nodes": {
		"project_membership": {
			"component": "project_membership",
			"inputs": {"team": presented, "ownership": presented},
			"policy_data": {},
		},
		"institutional_irb_approval": {
			"component": "institutional_irb_approval",
			"inputs": {"accreditation": presented, "irb": presented},
			"policy_data": {},
		},
		"irb_clearance": {
			"component": "irb_clearance",
			"inputs": {
				"approval": from_node("institutional_irb_approval", false),
				"affiliation": presented,
				"membership": from_node("project_membership", true),
			},
			"policy_data": {},
		},
		"ethics_approval_required": {
			"component": "ethics_approval_required",
			"inputs": {"clearance": from_node("irb_clearance", true), "use": presented},
			"policy_data": {},
		},
	},
	"capability": {
		"operation": "do_download",
		"requires": ["ethics_approval_required"],
		"parameters": {"channel_key": {"type": "publicKeyCredential", "role": "User", "claim": "key"}},
	},
	"trusted_issuers": {
		"AffiliationCredential": [],
		"EthicsCommitteeAccreditationCredential": [],
		"IRBApprovalCredential": [],
		"IRBClearanceCredential": [],
		"IntendedDataUseCredential": [],
		"ProjectMembershipCredential": [],
		"ProjectOwnershipCredential": [],
		"TeamCredential": [],
		"publicKeyCredential": [],
	},
}

view(t, i, issuer, trusted) := {
	"type": t, "issuer": issuer, "signer": issuer, "trusted": trusted,
	"subject": "did:example:subject", "claims": {}, "index": i, "proof_value": "",
}

chain := [
	view("TeamCredential", 0, "did:example:registry", true),
	view("ProjectOwnershipCredential", 1, "did:example:registry", true),
	view("EthicsCommitteeAccreditationCredential", 2, "did:example:registry", true),
	view("IRBApprovalCredential", 3, "did:example:dac", true),
	view("AffiliationCredential", 4, "did:example:registry", true),
	view("IntendedDataUseCredential", 5, "did:example:dac", true),
	view("publicKeyCredential", 6, "did:example:platform", true),
]

# A copy of x with one value set or removed, at a depth of up to four keys: what
# json.patch does, which regorus does not have.
replaced(x, k, v) := object.union(object.remove(x, [k]), {k: v})

set2(x, a, b, v) := replaced(x, a, replaced(x[a], b, v))

set3(x, a, b, c, v) := replaced(x, a, set2(x[a], b, c, v))

set4(x, a, b, c, d, v) := replaced(x, a, set3(x[a], b, c, d, v))

del2(x, a, b) := replaced(x, a, object.remove(x[a], [b]))

del3(x, a, b, c) := replaced(x, a, del2(x[a], b, c))

del4(x, a, b, c, d) := replaced(x, a, del3(x[a], b, c, d))
