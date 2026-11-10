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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "rego/policy_graph.h"
#include "rego/rego_evaluator.h"
#include "rego/rego_graph_combinators.h" // generated from pdo/rego/graph/*.rego

// A component is the package pf.components.<component id>, with an interface rule and
// an output rule.
static const std::string COMPONENT_PACKAGE("data.pf.components.");

// -----------------------------------------------------------------
// The graph is checked by the validator combinator before it is stored, so the code
// below reads it with parson directly (json_object_get_*, which, unlike the dotted
// lookups of ww::value, takes a key as it is).
// -----------------------------------------------------------------
static const JSON_Object *as_object(const ww::value::Value &value)
{
    return json_value_get_object(value.get());
}

static std::vector<std::string> keys_of(const JSON_Object *object)
{
    std::vector<std::string> keys;
    const size_t count = json_object_get_count(object);
    for (size_t i = 0; i < count; i++)
        keys.push_back(json_object_get_name(object, i));
    return keys;
}

// the sources of an input: one source object, or a list of them
static std::vector<const JSON_Object *> sources_of(const JSON_Value *raw)
{
    std::vector<const JSON_Object *> sources;
    if (json_value_get_type(raw) == JSONArray)
    {
        const JSON_Array *list = json_value_get_array(raw);
        for (size_t i = 0; i < json_array_get_count(list); i++)
            sources.push_back(json_array_get_object(list, i));
    }
    else
    {
        sources.push_back(json_value_get_object(raw));
    }
    return sources;
}

// names a component id may use: they become keys and package names
static bool valid_name(const char *name)
{
    if (name == nullptr || name[0] == '\0')
        return false;
    for (const char *c = name; *c != '\0'; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '_'))
            return false;
    return true;
}

static bool integral_index(const JSON_Value *value, int &index)
{
    if (json_value_get_type(value) != JSONNumber)
        return false;
    const double number = json_value_get_number(value);
    index = (int)number;
    return number >= 0 && (double)index == number;
}

bool ww::rego::policy_graph::checks_supplied_key(const ww::value::Object &input_spec)
{
    return json_object_get_boolean(as_object(input_spec), "supplied_key") == 1;
}

// -----------------------------------------------------------------
// validate_graph
// -----------------------------------------------------------------
bool ww::rego::policy_graph::validate_graph(
    const ww::value::Object &graph,
    const ww::value::Array &components,
    ww::value::Object &interfaces,
    std::string &error_msg)
{
    const JSON_Object *nodes = json_object_get_object(as_object(graph), "nodes");
    if (json_object_get_count(nodes) > REGO_GRAPH_MAX_NODES || components.get_count() > REGO_GRAPH_MAX_COMPONENTS)
    {
        error_msg.assign("invalid request, a policy graph has at most 32 nodes and 16 components");
        return false;
    }

    const size_t count = components.get_count();
    for (size_t i = 0; i < count; i++)
    {
        ww::value::Array pair;
        if (!components.get_value(i, pair) || pair.get_count() != 2)
        {
            error_msg.assign("invalid request, ill-formed component pair");
            return false;
        }
        const char *component_id = pair.get_string(0);
        const char *source = pair.get_string(1);
        if (!valid_name(component_id) || source == nullptr)
        {
            error_msg.assign("invalid request, ill-formed component pair");
            return false;
        }
        if (strlen(source) > REGO_GRAPH_MAX_SOURCE_BYTES)
        {
            error_msg.assign(std::string("invalid request, component ") + component_id + " is larger than 64 KB");
            return false;
        }
        if (json_object_has_value(as_object(interfaces), component_id))
        {
            error_msg.assign(std::string("invalid request, component ") + component_id + " is given twice");
            return false;
        }

        // a component defines exactly its own package
        const std::string package = COMPONENT_PACKAGE + component_id;
        std::string packages_json;
        if (!ww::rego::rego_evaluator::get_rego_packages(source, packages_json, error_msg))
            return false;
        ww::value::Array packages;
        if (!packages.deserialize(packages_json.c_str()) || packages.get_count() != 1 ||
            packages.get_string(0) == nullptr || package != packages.get_string(0))
        {
            error_msg.assign(std::string("invalid request, component ") + component_id +
                             " must define package pf.components." + component_id);
            return false;
        }

        std::string interface_json;
        if (!ww::rego::rego_evaluator::eval_rego(source, (package + ".interface").c_str(), "{}", interface_json, error_msg))
            return false;
        ww::value::Object iface;
        ww::value::Object inputs;
        if (!iface.deserialize(interface_json.c_str()) || !iface.get_value("inputs", inputs))
        {
            error_msg.assign(std::string("invalid request, component ") + component_id + " has an ill-formed interface");
            return false;
        }
        if (json_object_get_count(as_object(inputs)) > REGO_GRAPH_MAX_INPUTS)
        {
            error_msg.assign(std::string("invalid request, component ") + component_id + " has more than 8 inputs");
            return false;
        }
        if (!interfaces.set_value(component_id, iface))
        {
            error_msg.assign("unexpected error, failed to collect the interfaces");
            return false;
        }
    }

    // the validator combinator checks the rest, and lists every problem
    ww::value::Object validator_input;
    std::string input_json;
    if (!validator_input.set_value("graph", graph) || !validator_input.set_value("interfaces", interfaces) ||
        !validator_input.serialize(input_json))
    {
        error_msg.assign("unexpected error, failed to serialize the validator input");
        return false;
    }

    std::string problems_json;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_GRAPH_VALIDATOR, "data.validate.result", input_json, problems_json, error_msg))
        return false;

    ww::value::Array problems;
    if (!problems.deserialize(problems_json.c_str()))
    {
        error_msg.assign("unexpected error, the validator returned an ill-formed result");
        return false;
    }
    if (problems.get_count() > 0)
    {
        const char *first = problems.get_string(0);
        error_msg.assign(std::string("invalid request, ") + (first == nullptr ? "ill-formed policy graph" : first));
        if (problems.get_count() > 1)
            error_msg.append(" (and " + std::to_string(problems.get_count() - 1) + " more problems)");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------
// compute_alternatives
//   A bundle is a set of (role, credential type). A presented input needs its own
//   type; a node input needs what its producer needs; accept_presented offers both.
//   A node needs one bundle from each of its inputs. Bundles that include another are
//   dropped, and more than 64 alternatives anywhere is refused.
// -----------------------------------------------------------------
typedef std::set<std::pair<std::string, std::string>> Bundle;
typedef std::vector<Bundle> Bundles;

static Bundles minimal(const Bundles &bundles)
{
    const std::set<Bundle> unique(bundles.begin(), bundles.end());
    Bundles out;
    for (const Bundle &b : unique)
    {
        bool includes_another = false;
        for (const Bundle &other : unique)
        {
            if (other.size() < b.size() && std::includes(b.begin(), b.end(), other.begin(), other.end()))
            {
                includes_another = true;
                break;
            }
        }
        if (!includes_another)
            out.push_back(b);
    }
    return out;
}

static bool product(const Bundles &left, const Bundles &right, Bundles &out, std::string &error_msg)
{
    Bundles all;
    for (const Bundle &a : left)
    {
        for (const Bundle &b : right)
        {
            Bundle both(a);
            both.insert(b.begin(), b.end());
            all.push_back(both);
        }
    }
    out = minimal(all);
    if (out.size() > REGO_GRAPH_MAX_ALTERNATIVES)
    {
        error_msg.assign("invalid request, the graph has more than 64 requirement alternatives");
        return false;
    }
    return true;
}

static bool node_alternatives(
    const JSON_Object *nodes,
    const JSON_Object *interfaces,
    const std::string &node_id,
    std::map<std::string, Bundles> &memo,
    Bundles &out,
    std::string &error_msg)
{
    const auto known = memo.find(node_id);
    if (known != memo.end())
    {
        out = known->second;
        return true;
    }

    const JSON_Object *node = json_object_get_object(nodes, node_id.c_str());
    const JSON_Object *iface = json_object_get_object(interfaces, json_object_get_string(node, "component"));
    const JSON_Object *specs = json_object_get_object(iface, "inputs");
    const JSON_Object *inputs = json_object_get_object(node, "inputs");

    std::vector<std::string> names = keys_of(inputs);
    std::sort(names.begin(), names.end());

    Bundles alts = {Bundle()};
    for (const std::string &name : names)
    {
        const JSON_Object *spec = json_object_get_object(specs, name.c_str());
        const Bundle own = {{json_object_get_string(spec, "role"), json_object_get_string(spec, "type")}};

        Bundles input_alts = {Bundle()};
        for (const JSON_Object *source : sources_of(json_object_get_value(inputs, name.c_str())))
        {
            Bundles options;
            if (strcmp(json_object_get_string(source, "from"), "presented") == 0)
            {
                options = {own};
            }
            else
            {
                if (!node_alternatives(nodes, interfaces, json_object_get_string(source, "node"), memo, options, error_msg))
                    return false;
                if (json_object_get_boolean(source, "accept_presented") == 1)
                {
                    options.push_back(own);
                    options = minimal(options);
                }
            }
            if (!product(input_alts, options, input_alts, error_msg))
                return false;
        }
        if (!product(alts, input_alts, alts, error_msg))
            return false;
    }

    memo[node_id] = alts;
    out = alts;
    return true;
}

bool ww::rego::policy_graph::compute_alternatives(
    const ww::value::Object &graph,
    const ww::value::Object &interfaces,
    ww::value::Array &alternatives,
    std::string &error_msg)
{
    std::map<std::string, Bundles> memo;
    Bundles bundles;
    if (!node_alternatives(json_object_get_object(as_object(graph), "nodes"), as_object(interfaces),
                           json_object_get_string(as_object(graph), "root"), memo, bundles, error_msg))
        return false;

    // smallest first; minimal() keeps bundles of one size in their own order
    Bundles ordered;
    size_t largest = 0;
    for (const Bundle &bundle : bundles)
        largest = std::max(largest, bundle.size());
    for (size_t size = 0; size <= largest; size++)
        for (const Bundle &bundle : bundles)
            if (bundle.size() == size)
                ordered.push_back(bundle);

    for (const Bundle &bundle : ordered)
    {
        // a bundle is ordered by role, then type, so each role's types come out sorted
        JSON_Value *by_role_value = json_value_init_object();
        JSON_Object *by_role = json_value_get_object(by_role_value);
        for (const auto &role_type : bundle)
        {
            if (!json_object_has_value(by_role, role_type.first.c_str()))
                json_object_set_value(by_role, role_type.first.c_str(), json_value_init_array());
            json_array_append_string(json_object_get_array(by_role, role_type.first.c_str()), role_type.second.c_str());
        }
        ww::value::Object alternative;
        const bool kept = alternative.set(by_role_value) != nullptr && alternatives.append_value(alternative);
        json_value_free(by_role_value);
        if (!kept)
        {
            error_msg.assign("unexpected error, failed to collect the alternatives");
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------
// plan_graph
// -----------------------------------------------------------------
bool ww::rego::policy_graph::plan_graph(
    const ww::value::Object &graph,
    const ww::value::Object &interfaces,
    const ww::value::Object &presented,
    ww::value::Object &plan,
    std::string &error_msg)
{
    ww::value::Object planner_input;
    std::string input_json;
    if (!planner_input.set_value("graph", graph) || !planner_input.set_value("interfaces", interfaces) ||
        !planner_input.set_value("presented", presented) || !planner_input.serialize(input_json))
    {
        error_msg.assign("unexpected error, failed to serialize the planner input");
        return false;
    }

    std::string plan_json;
    if (!ww::rego::rego_evaluator::eval_rego(REGO_GRAPH_PLANNER, "data.plan.result", input_json, plan_json, error_msg))
        return false;
    if (!plan.deserialize(plan_json.c_str()))
    {
        error_msg.assign("unexpected error, the planner returned an ill-formed plan");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------
// run_graph
// -----------------------------------------------------------------

// A presented credential as a component reads it: the contract's view, with its index
// as its evidence.
static JSON_Value *as_credential(const ww::value::Object &view)
{
    const JSON_Object *v = as_object(view);
    JSON_Value *credential = json_value_init_object();
    JSON_Object *c = json_value_get_object(credential);
    json_object_set_string(c, "type", json_object_get_string(v, "type"));
    json_object_set_string(c, "issuer", json_object_get_string(v, "issuer"));
    json_object_set_string(c, "subject", json_object_get_string(v, "subject"));
    json_object_set_value(c, "claims", json_value_deep_copy(json_object_get_value(v, "claims")));
    JSON_Value *evidence = json_value_init_array();
    json_array_append_number(json_value_get_array(evidence), json_object_get_number(v, "index"));
    json_object_set_value(c, "evidence", evidence);
    return credential;
}

static bool exactly_keys(const JSON_Object *object, const std::set<std::string> &keys)
{
    if (object == nullptr || json_object_get_count(object) != keys.size())
        return false;
    for (const std::string &key : keys)
        if (!json_object_has_value(object, key.c_str()))
            return false;
    return true;
}

static bool nonempty_string(const JSON_Object *object, const char *key)
{
    const char *value = json_object_get_string(object, key);
    return value != nullptr && value[0] != '\0';
}

// A component's output credential: of the component's output type, about a subject,
// with claims (a capability's being { operation: { name, parameters } }), resting only
// on evidence the node was given; with a key check for each credential it checked
// against a key it supplies.
static bool well_formed(
    const JSON_Value *value,
    const JSON_Object *iface,
    bool returns_key_checks,
    const std::set<int> &allowed,
    const std::set<int> &key_bound)
{
    const JSON_Object *credential = json_value_get_object(value);
    std::set<std::string> keys = {"type", "subject", "claims", "evidence"};
    if (returns_key_checks)
        keys.insert("key_checks");
    if (!exactly_keys(credential, keys))
        return false;

    const char *type = json_object_get_string(credential, "type");
    if (type == nullptr || strcmp(type, json_object_get_string(iface, "output")) != 0)
        return false;
    if (!nonempty_string(credential, "subject"))
        return false;

    const JSON_Object *claims = json_object_get_object(credential, "claims");
    if (claims == nullptr)
        return false;
    if (strcmp(type, "Capability") == 0)
    {
        const JSON_Object *operation = json_object_get_object(claims, "operation");
        if (!exactly_keys(claims, {"operation"}) || !exactly_keys(operation, {"name", "parameters"}) ||
            !nonempty_string(operation, "name") || json_object_get_object(operation, "parameters") == nullptr)
            return false;
    }

    const JSON_Array *evidence = json_object_get_array(credential, "evidence");
    if (evidence == nullptr)
        return false;
    for (size_t i = 0; i < json_array_get_count(evidence); i++)
    {
        int index;
        if (!integral_index(json_array_get_value(evidence, i), index) || allowed.count(index) == 0)
            return false;
    }

    if (returns_key_checks)
    {
        const JSON_Array *checks = json_object_get_array(credential, "key_checks");
        if (checks == nullptr)
            return false;
        for (size_t i = 0; i < json_array_get_count(checks); i++)
        {
            const JSON_Object *check = json_array_get_object(checks, i);
            int index;
            if (!exactly_keys(check, {"index", "key", "key_type"}) ||
                !integral_index(json_object_get_value(check, "index"), index) || key_bound.count(index) == 0 ||
                !nonempty_string(check, "key"))
                return false;
            const char *key_type = json_object_get_string(check, "key_type");
            if (key_type == nullptr || (strcmp(key_type, "ec") != 0 && strcmp(key_type, "rsa") != 0))
                return false;
        }
    }
    return true;
}

// The inputs of a node, from the plan: presented credentials by index, and the outputs
// of the nodes it reads. allowed collects the evidence the node may cite, key_bound the
// credentials it must check against a key it supplies.
static bool node_inputs(
    const char *node_id,
    const JSON_Object *specs,
    const JSON_Object *node_bindings,
    const std::vector<ww::value::Object> &views,
    const JSON_Object *produced,
    JSON_Object *inputs,
    std::set<int> &allowed,
    std::set<int> &key_bound,
    std::string &error_msg)
{
    for (const std::string &name : keys_of(node_bindings))
    {
        const bool supplied_key =
            json_object_get_boolean(json_object_get_object(specs, name.c_str()), "supplied_key") == 1;
        const JSON_Array *entries = json_object_get_array(node_bindings, name.c_str());

        JSON_Value *input_value = json_value_init_array();
        JSON_Array *input = json_value_get_array(input_value);
        bool every_source_yields = true;
        for (size_t e = 0; e < json_array_get_count(entries); e++)
        {
            const JSON_Object *entry = json_array_get_object(entries, e);
            size_t yielded = 0;
            if (strcmp(json_object_get_string(entry, "from"), "presented") == 0)
            {
                const JSON_Array *indices = json_object_get_array(entry, "indices");
                for (size_t k = 0; k < json_array_get_count(indices); k++)
                {
                    const int index = (int)json_array_get_number(indices, k);
                    if (index < 0 || (size_t)index >= views.size())
                    {
                        json_value_free(input_value);
                        error_msg.assign("unexpected error, the plan names an unknown credential");
                        return false;
                    }
                    json_array_append_value(input, as_credential(views[index]));
                    allowed.insert(index);
                    if (supplied_key)
                        key_bound.insert(index);
                    yielded++;
                }
            }
            else
            {
                const JSON_Array *creds = json_object_get_array(produced, json_object_get_string(entry, "node"));
                for (size_t k = 0; k < json_array_get_count(creds); k++)
                {
                    const JSON_Value *cred = json_array_get_value(creds, k);
                    const JSON_Array *evidence = json_object_get_array(json_value_get_object(cred), "evidence");
                    for (size_t x = 0; x < json_array_get_count(evidence); x++)
                        allowed.insert((int)json_array_get_number(evidence, x));
                    json_array_append_value(input, json_value_deep_copy(cred));
                    yielded++;
                }
            }
            every_source_yields = every_source_yields && yielded > 0;
        }

        // an input with several sources takes them all, or nothing unless each yields one
        if (!every_source_yields)
            json_array_clear(input);
        if (json_array_get_count(input) > REGO_GRAPH_MAX_CREDENTIALS)
        {
            json_value_free(input_value);
            error_msg.assign(std::string("invalid request, node ") + node_id + " input " + name +
                             " takes more than 64 credentials");
            return false;
        }
        json_object_set_value(inputs, name.c_str(), input_value);
    }
    return true;
}

// Run one node in its own engine over { inputs, policy_data, request } and keep what it
// returns in produced, under the node's id.
static bool run_node(
    const char *node_id,
    const JSON_Object *nodes,
    const JSON_Object *interfaces,
    const JSON_Object *bindings,
    const std::map<std::string, std::string> &sources,
    const std::vector<ww::value::Object> &views,
    const ww::value::Object &policy_data,
    const ww::value::Object &request,
    JSON_Object *produced,
    std::string &error_msg)
{
    const char *component_id = json_object_get_string(json_object_get_object(nodes, node_id), "component");
    const JSON_Object *iface = json_object_get_object(interfaces, component_id);
    const JSON_Object *specs = json_object_get_object(iface, "inputs");

    bool returns_key_checks = false;
    for (const std::string &name : keys_of(specs))
        returns_key_checks = returns_key_checks ||
            json_object_get_boolean(json_object_get_object(specs, name.c_str()), "supplied_key") == 1;

    const JSON_Value *node_data = json_object_get_value(as_object(policy_data), node_id);
    if (json_value_get_type(node_data) != JSONObject)
    {
        error_msg.assign(std::string("invalid request, no policy data object for node ") + node_id);
        return false;
    }

    JSON_Value *component_input = json_value_init_object();
    JSON_Value *inputs_value = json_value_init_object();
    json_object_set_value(json_value_get_object(component_input), "inputs", inputs_value);
    json_object_set_value(json_value_get_object(component_input), "policy_data", json_value_deep_copy(node_data));
    json_object_set_value(json_value_get_object(component_input), "request", json_value_deep_copy(request.get()));

    std::set<int> allowed;
    std::set<int> key_bound;
    if (!node_inputs(node_id, specs, json_object_get_object(bindings, node_id), views, produced,
                     json_value_get_object(inputs_value), allowed, key_bound, error_msg))
    {
        json_value_free(component_input);
        return false;
    }

    char *input_json = json_serialize_to_string(component_input);
    json_value_free(component_input);
    if (input_json == nullptr)
    {
        error_msg.assign("unexpected error, failed to serialize the component input");
        return false;
    }

    const auto source = sources.find(component_id);
    std::string output_json;
    const std::string rule = COMPONENT_PACKAGE + component_id + ".output";
    const bool evaluated = source != sources.end() && ww::rego::rego_evaluator::eval_rego(
        source->second.c_str(), rule.c_str(), input_json, output_json, error_msg);
    json_free_serialized_string(input_json);
    if (!evaluated)
        return false;

    JSON_Value *output = json_parse_string(output_json.c_str());
    const JSON_Array *creds = json_value_get_array(output);
    bool ok = creds != nullptr && json_array_get_count(creds) <= REGO_GRAPH_MAX_CREDENTIALS;
    for (size_t k = 0; ok && k < json_array_get_count(creds); k++)
        ok = well_formed(json_array_get_value(creds, k), iface, returns_key_checks, allowed, key_bound);
    if (!ok)
    {
        json_value_free(output);
        error_msg.assign(std::string("unexpected error, node ") + node_id + " returned an ill-formed output");
        return false;
    }
    json_object_set_value(produced, node_id, output);
    return true;
}

bool ww::rego::policy_graph::run_graph(
    const ww::value::Object &graph,
    const ww::value::Array &components,
    const ww::value::Object &interfaces,
    const ww::value::Object &plan,
    const std::vector<ww::value::Object> &views,
    const ww::value::Object &policy_data,
    const ww::value::Object &request,
    ww::value::Object &outputs,
    std::string &error_msg)
{
    std::map<std::string, std::string> sources;
    for (size_t i = 0; i < components.get_count(); i++)
    {
        ww::value::Array pair;
        components.get_value(i, pair);
        sources[pair.get_string(0)] = pair.get_string(1);
    }

    const JSON_Object *nodes = json_object_get_object(as_object(graph), "nodes");
    const JSON_Array *order = json_object_get_array(as_object(plan), "order");
    const JSON_Object *bindings = json_object_get_object(as_object(plan), "bindings");

    JSON_Value *produced = json_value_init_object();
    bool ok = true;
    for (size_t o = 0; ok && o < json_array_get_count(order); o++)
        ok = run_node(json_array_get_string(order, o), nodes, as_object(interfaces), bindings, sources, views,
                      policy_data, request, json_value_get_object(produced), error_msg);
    if (ok && outputs.set(produced) == nullptr)
    {
        error_msg.assign("unexpected error, failed to keep the outputs");
        ok = false;
    }
    json_value_free(produced);
    return ok;
}

// -----------------------------------------------------------------
// decide
// -----------------------------------------------------------------
bool ww::rego::policy_graph::decide(
    const ww::value::Object &graph,
    const ww::value::Object &outputs,
    bool &allowed,
    std::string &subject,
    ww::value::Object &operation,
    std::string &reason,
    std::string &error_msg)
{
    const JSON_Array *capabilities =
        json_object_get_array(as_object(outputs), json_object_get_string(as_object(graph), "root"));
    allowed = false;
    if (json_array_get_count(capabilities) == 0)
    {
        reason.assign("the root issued no capability");
        return true;
    }

    std::string first;
    for (size_t k = 0; k < json_array_get_count(capabilities); k++)
    {
        const JSON_Object *capability = json_array_get_object(capabilities, k);
        JSON_Value *verdict = json_value_init_object();
        json_object_set_string(json_value_get_object(verdict), "subject", json_object_get_string(capability, "subject"));
        json_object_set_value(json_value_get_object(verdict), "operation",
                              json_value_deep_copy(json_object_dotget_value(capability, "claims.operation")));
        char *serialized = json_serialize_to_string(verdict);
        json_value_free(verdict);
        if (serialized == nullptr)
        {
            error_msg.assign("unexpected error, failed to serialize a capability");
            return false;
        }
        const std::string this_one(serialized);
        json_free_serialized_string(serialized);
        if (k == 0)
        {
            first = this_one;
        }
        else if (this_one != first)
        {
            reason.assign("the capabilities disagree");
            return true;
        }
    }

    const JSON_Object *capability = json_array_get_object(capabilities, 0);
    subject.assign(json_object_get_string(capability, "subject"));
    if (operation.set(json_object_dotget_value(capability, "claims.operation")) == nullptr)
    {
        error_msg.assign("unexpected error, failed to read the operation");
        return false;
    }
    allowed = true;
    return true;
}
