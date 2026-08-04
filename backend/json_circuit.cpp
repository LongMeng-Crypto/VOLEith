/* SPDX-License-Identifier: MIT */

#include "json_circuit.hpp"

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <charconv>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>

namespace vole_backend {
namespace {

using Tree = boost::property_tree::ptree;

void require_keys(const Tree& tree, std::initializer_list<std::string_view> allowed,
                  std::string_view where) {
  std::set<std::string> seen;
  for (const auto& [key, unused] : tree) {
    (void)unused;
    if (key.empty()) throw std::invalid_argument(std::string(where) + " must be an object");
    if (!seen.insert(key).second)
      throw std::invalid_argument(std::string(where) + " contains duplicate key: " + key);
    bool found = false;
    for (const auto candidate : allowed) found |= key == candidate;
    if (!found) throw std::invalid_argument(std::string(where) + " contains unknown key: " + key);
  }
}

std::string scalar(const Tree& tree, const char* key, std::string_view where) {
  const auto child = tree.get_child_optional(key);
  if (!child || !child->empty())
    throw std::invalid_argument(std::string(where) + " requires scalar field: " + key);
  return child->data();
}

std::uint32_t uint32_scalar(const Tree& tree, const char* key, std::string_view where) {
  const auto text = scalar(tree, key, where);
  std::uint32_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() || text.empty())
    throw std::invalid_argument(std::string(where) + " field is not a uint32: " + key);
  return value;
}

const Tree& required_child(const Tree& tree, const char* key, std::string_view where) {
  const auto child = tree.get_child_optional(key);
  if (!child) throw std::invalid_argument(std::string(where) + " requires field: " + key);
  return *child;
}

} // namespace

BinaryCircuit compile_json_circuit(std::string_view json) {
  Tree root;
  std::istringstream stream{std::string(json)};
  try {
    boost::property_tree::read_json(stream, root);
  } catch (const boost::property_tree::json_parser::json_parser_error& error) {
    throw std::invalid_argument(std::string("invalid circuit JSON: ") + error.message());
  }
  require_keys(root, {"format", "version", "nodes", "outputs"}, "root");
  if (scalar(root, "format", "root") != "vole-binary-circuit")
    throw std::invalid_argument("unsupported circuit JSON format");
  if (uint32_scalar(root, "version", "root") != 1)
    throw std::invalid_argument("unsupported circuit JSON version");

  std::vector<Node> nodes;
  const auto& json_nodes = required_child(root, "nodes", "root");
  for (const auto& [array_key, item] : json_nodes) {
    if (!array_key.empty()) throw std::invalid_argument("nodes must be an array");
    const auto where = "node[" + std::to_string(nodes.size()) + "]";
    const auto op = scalar(item, "op", where);
    if (op == "constant") {
      require_keys(item, {"op", "value"}, where);
      const auto value = uint32_scalar(item, "value", where);
      if (value > 1) throw std::invalid_argument(where + " constant must be 0 or 1");
      nodes.push_back({Op::Constant, 0, 0, value != 0});
    } else if (op == "private") {
      require_keys(item, {"op"}, where);
      nodes.push_back({Op::PrivateInput, 0, 0, false});
    } else if (op == "public") {
      require_keys(item, {"op"}, where);
      nodes.push_back({Op::PublicInput, 0, 0, false});
    } else if (op == "xor" || op == "and") {
      require_keys(item, {"op", "lhs", "rhs"}, where);
      nodes.push_back({op == "xor" ? Op::Xor : Op::And,
                       uint32_scalar(item, "lhs", where),
                       uint32_scalar(item, "rhs", where), false});
    } else {
      throw std::invalid_argument(where + " has unknown op: " + op);
    }
  }

  std::vector<Wire> outputs;
  const auto& json_outputs = required_child(root, "outputs", "root");
  for (const auto& [array_key, item] : json_outputs) {
    if (!array_key.empty() || !item.empty()) throw std::invalid_argument("outputs must be an array of uint32");
    std::uint32_t value = 0;
    const auto& text = item.data();
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || text.empty())
      throw std::invalid_argument("output is not a uint32");
    outputs.push_back(value);
  }
  return BinaryCircuit::from_canonical(std::move(nodes), std::move(outputs));
}

} // namespace vole_backend
