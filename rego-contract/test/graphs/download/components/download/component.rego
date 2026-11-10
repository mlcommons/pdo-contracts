package pf.components.download

import rego.v1

# The do_download capability for the key the request names, when the key's holder holds the
# grant.
#   key    public_key        about the applicant, key
#   grant  membership_grant  about the applicant
# -> Capability do_download {channel_key}.
interface := {
	"output": "Capability",
	"inputs": {
		"key": {"type": "public_key", "role": "applicant"},
		"grant": {"type": "membership_grant", "role": "applicant"},
	},
	"policy_data_schema": {},
}

output := [capability |
	some key in input.inputs.key
	key.claims.key == input.request.channel_key
	some grant in input.inputs.grant
	grant.subject == key.subject
	capability := {
		"type": "Capability",
		"subject": key.subject,
		"claims": {"operation": {"name": "do_download", "parameters": {"channel_key": key.claims.key}}},
		"evidence": sort(array.concat(key.evidence, grant.evidence)),
	}
]
