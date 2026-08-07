// Reading the two JSON inputs: the lexical findings, and the rule table that
// says what each finding's rule is about.
#pragma once

#include "Gate.h"

#include "llvm/ADT/StringRef.h"

#include <string>
#include <vector>

namespace intentgate {

/// Parse a findings file. Accepts either a bare array of findings or an object
/// with a `findings` array (so the same file can carry a `root` alongside).
/// Returns false with `Err` filled on malformed input — never a partial list,
/// because a silently short list is a check that did not run.
bool loadFindings(llvm::StringRef Path, std::vector<LexicalFinding> &Out, std::string &Err);

/// Parse a rule table. Same shape discipline as above.
bool loadRules(llvm::StringRef Path, std::vector<Rule> &Out, std::string &Err);

/// The table compiled into the plugin, used when no `rules=` argument is given.
/// Kept identical to rules/default-rules.json; the load test in README.md is
/// what keeps the two from drifting.
const std::vector<Rule> &builtinRules();

/// Find the rule with this id, or null.
const Rule *findRule(const std::vector<Rule> &Rules, llvm::StringRef Id);

/// Pick the rule target a finding is about: the LONGEST of the rule's targets
/// that occurs as a substring of the finding's matched text. Returns empty when
/// none occurs, which is Deferred(D3) rather than a guess.
std::string selectTarget(const Rule &R, llvm::StringRef MatchText);

} // namespace intentgate
