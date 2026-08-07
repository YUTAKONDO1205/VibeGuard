// Finding -> Derived Requirement. DERIVATION.md is the specification; this is
// the implementation, and the table at the end of DERIVATION.md maps every rule
// number there to a named branch here.
#pragma once

#include "Classifier.h"
#include "Gate.h"

#include <vector>

namespace intentgate {

/// Derive requirements from classified findings.
///
/// The shape of the mapping, stated once:
///   - the RULE decides the requirement's kind,
///   - the AST decides the scope, the expected count, and whether a requirement
///     is emitted at all,
///   - a Deferred verdict emits NOTHING, because a requirement that says
///     "nothing is required" is indistinguishable from a check that did not run
///     (interfaces.md §3, §7).
std::vector<DerivedRequirement> derive(const std::vector<VerdictRecord> &Verdicts,
                                       const std::vector<Rule> &Rules, const Inventory &Inv);

/// The checkpoint list a requirement kind defaults to when the rule does not
/// name one. Exposed so DERIVATION.md's table can be checked against it.
const std::vector<std::string> &defaultCheckpoints(RequirementKind K);

} // namespace intentgate
