/* Copyright 2026 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"

// The contract initialization hook, the trusted-issuer methods and get_policy_data
// are inherited from ww::identity::policy_agent (registered directly in the dispatch
// table); the methods that hold and run the policy are declared here.

// The top level of a policy graph; the graph validator combinator checks the rest.
//   { "version": 2, "name", "root", "nodes": { <node>: { component, inputs, policy_data } },
//     "trusted_issuers": { <credential type>: [ <DID>, ... ] } }
#define REGO_POLICY_GRAPH_SCHEMA                \
    "{"                                         \
        SCHEMA_KW(version, 0) ","               \
        SCHEMA_KW(name, "") ","                 \
        SCHEMA_KW(root, "") ","                 \
        SCHEMA_KW(nodes, {}) ","                \
        SCHEMA_KW(trusted_issuers, {})          \
    "}"

// set_rego_policy: set the policy, a graph of components, once (see
// rego/policy_graph.h and docs/policy_graph.md). Trusting the agent means trusting
// this one policy, so it never changes.
//   { "policy_graph": <graph>, "components": [ [ component_id, source ], ... ] }
#define REGO_POLICY_AGENT_SET_POLICY_PARAM_SCHEMA                       \
    "{"                                                                 \
        SCHEMA_KWS(policy_graph, REGO_POLICY_GRAPH_SCHEMA) ","          \
        SCHEMA_KWS(components, "[[\"\"]]")                              \
    "}"

// set_policy_data: replace one node's policy data
#define REGO_POLICY_AGENT_SET_POLICY_DATA_PARAM_SCHEMA  \
    "{"                                                 \
        SCHEMA_KW(node, "") ","                         \
        SCHEMA_KW(policy_data, {})                      \
    "}"

// issue_policy_credential: supply the presentations to judge under the
// "presentation" keyword as an object keyed by role,
// { role: <verifiable presentation>, ... }, and the values the requester
// declares (for instance a channel key) under "request", handed to every
// component as input.request. Each presentation is checked against the roles the
// policy's requirement alternatives read, so this top-level schema only requires
// objects.
#define REGO_POLICY_AGENT_ISSUE_PARAM_SCHEMA            \
    "{"                                                 \
        SCHEMA_KW(presentation, {}) ","                 \
        SCHEMA_KW(request, {})                          \
    "}"

// The operation a policy_decision authorizes: an operation name and its
// parameters. The parameters are opaque (their shape is decided by the operation
// itself), so the schema can only require an object. This is the shape of a
// policy_decision credential's claims, parsed by the rego_token to build the
// guardian capability.
//   { "name": <operation name>, "parameters": { ... } }
#define REGO_OPERATION_SCHEMA                   \
    "{"                                         \
        SCHEMA_KW(name, "") ","                 \
        SCHEMA_KWS(parameters, "{}")            \
    "}"

namespace ww
{
namespace rego
{
namespace rego_policy_agent
{
    // set the policy, a graph of components, once
    bool set_rego_policy(const Message& msg, const Environment& env, Response& rsp);

    // return the graph, its components and the hash of both
    bool get_rego_policy(const Message& msg, const Environment& env, Response& rsp);

    // return every bundle of presented credentials that can satisfy the policy, by
    // role, smallest first
    bool get_requirements(const Message& msg, const Environment& env, Response& rsp);

    // replace one node's policy data
    bool set_policy_data(const Message& msg, const Environment& env, Response& rsp);

    // plan and run the policy over the presentations, verify every credential the
    // components were given, and -- if the root issued a capability -- sign it as a
    // policy_decision credential
    bool issue_policy_credential(const Message& msg, const Environment& env, Response& rsp);

}; // rego_policy_agent
}; // rego
}; // ww
