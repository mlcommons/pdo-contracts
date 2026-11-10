package pf.components.member

import rego.v1

# The applicant's membership names an institution the owner allows.
#   membership  membership  about the applicant, institution
# -> membership_grant about the applicant.
interface := {
	"output": "membership_grant",
	"inputs": {"membership": {"type": "membership", "role": "applicant"}},
	"policy_data_schema": {
		"type": "object",
		"properties": {"allowedInstitutions": {"type": "array", "items": {"type": "string"}}},
		"required": ["allowedInstitutions"],
	},
}

output := [grant |
	some membership in input.inputs.membership
	membership.claims.institution in input.policy_data.allowedInstitutions
	grant := {
		"type": "membership_grant",
		"subject": membership.subject,
		"claims": {},
		"evidence": membership.evidence,
	}
]
