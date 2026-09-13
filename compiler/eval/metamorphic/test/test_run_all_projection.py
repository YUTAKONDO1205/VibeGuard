#!/usr/bin/env python3
"""The two things run-all.sh reads before it sweeps, and the refusals in each.

WHY THIS FILE

`run-all.sh` is a shell script, and nothing in CI runs THIS one. (CI does run shell
scripts -- three of them, at `ci.yml:661`, `:670` and `:750` -- so the claim is about
this file, not about the repository; an earlier version of this paragraph said the
repository runs none, which is false.)
What it decides, though, is not shell: it is (a) which configurations exist and
whether they could express the survival axis at all, and (b) whether the results
directory it is about to grade holds exactly the documents the catalogue accounts
for. Both were written as Python files rather than as `python3 -c` fragments
precisely so that they could be tested here, because the refusals are the whole
value -- a projection that silently returned the wrong set would produce a sweep
that looked complete and graded half a lane.

No compiler, no lab, no plugin. Every case is a catalogue or a directory built in
a temporary directory.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LANE = os.path.dirname(HERE)
READ_CONFIGS = os.path.join(LANE, "scripts", "read-configurations.py")
ACCOUNT = os.path.join(LANE, "scripts", "account-for-documents.py")
CATALOGUE = os.path.join(LANE, "catalogue.json")


def run(script, *args):
    p = subprocess.run([sys.executable, script, *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def catalogue_with(configurations):
    """The tracked catalogue with its `configurations` replaced, in a temp file."""
    with open(CATALOGUE, encoding="utf-8") as fh:
        cat = json.load(fh)
    cat["configurations"] = configurations
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cat, fh)
    return path


class ReadConfigurations(unittest.TestCase):
    def test_the_tracked_catalogue_projects_to_tab_separated_lines(self):
        rc, out, err = run(READ_CONFIGS, CATALOGUE)
        self.assertEqual(rc, 0, err)
        rows = [ln.split("\t") for ln in out.strip().split("\n")]
        self.assertTrue(len(rows) >= 2,
                        "the tracked catalogue projects to %d configuration(s); a lane with "
                        "fewer than two cannot hold both an unfolded and a folded reading"
                        % len(rows))
        for row in rows:
            self.assertEqual(len(row), 2, row)
            self.assertTrue(row[1].startswith("-O"), row)

    def test_the_order_is_the_catalogues_order(self):
        # run-all.sh measures in the order these lines arrive, and the order is a
        # property of the table rather than of whatever a dict iteration gives.
        rc, out, _ = run(READ_CONFIGS, CATALOGUE)
        self.assertEqual(rc, 0)
        with open(CATALOGUE, encoding="utf-8") as fh:
            declared = [c["runId"] for c in json.load(fh)["configurations"]]
        self.assertEqual([ln.split("\t")[0] for ln in out.strip().split("\n")], declared)

    def test_a_catalogue_with_no_configurations_is_refused(self):
        path = catalogue_with([])
        try:
            rc, out, err = run(READ_CONFIGS, path)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertIn("no configurations", err)
        finally:
            os.unlink(path)

    def test_a_catalogue_no_r2b_cell_could_move_in_is_refused(self):
        # THE case this file exists for. A catalogue edited down to -O0 alone
        # describes a lane every sweep of which check-meta.py refuses, and the
        # refusal has to arrive before the first compile rather than after the
        # last grade.
        path = catalogue_with([
            {"runId": "O0", "opt": "-O0", "why": "x", "r2bCanMove": False},
            {"runId": "Og", "opt": "-Og", "why": "x", "r2bCanMove": False},
        ])
        try:
            rc, out, err = run(READ_CONFIGS, path)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "")
            self.assertIn("r2bCanMove true", err)
            self.assertIn("survival-axis fence", err)
        finally:
            os.unlink(path)

    def test_one_mover_among_several_is_enough(self):
        path = catalogue_with([
            {"runId": "O0", "opt": "-O0", "why": "x", "r2bCanMove": False},
            {"runId": "O2", "opt": "-O2", "why": "x", "r2bCanMove": True},
        ])
        try:
            rc, out, err = run(READ_CONFIGS, path)
            self.assertEqual(rc, 0, err)
            self.assertEqual(out, "O0\t-O0\nO2\t-O2\n")
        finally:
            os.unlink(path)

    def test_r2bcanmove_is_not_optional(self):
        # A configuration that does not say is a configuration nobody decided
        # about, and a missing key read as falsey would let the fence above pass
        # for the wrong reason.
        path = catalogue_with([{"runId": "O2", "opt": "-O2", "why": "x"}])
        try:
            rc, _, err = run(READ_CONFIGS, path)
            self.assertEqual(rc, 1)
            self.assertIn("r2bCanMove", err)
        finally:
            os.unlink(path)

    def test_a_duplicated_run_id_is_refused(self):
        path = catalogue_with([
            {"runId": "O2", "opt": "-O2", "why": "x", "r2bCanMove": True},
            {"runId": "O2", "opt": "-O3", "why": "x", "r2bCanMove": True},
        ])
        try:
            rc, _, err = run(READ_CONFIGS, path)
            self.assertEqual(rc, 1)
            self.assertIn("same runId twice", err)
        finally:
            os.unlink(path)

    def test_an_unreadable_catalogue_is_refused_not_treated_as_empty(self):
        rc, _, err = run(READ_CONFIGS, os.path.join(HERE, "no-such-catalogue.json"))
        self.assertEqual(rc, 1)
        self.assertIn("could not read", err)


class AccountForDocuments(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.reports = os.path.join(self.tmp, "_results")
        os.makedirs(self.reports)
        self.cat = catalogue_with([
            {"runId": "O0", "opt": "-O0", "why": "x", "r2bCanMove": False},
            {"runId": "O2", "opt": "-O2", "why": "x", "r2bCanMove": True},
        ])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.unlink(self.cat)

    def touch(self, name):
        with open(os.path.join(self.reports, name), "w", encoding="utf-8") as fh:
            fh.write("{}\n")

    def test_one_document_per_declared_configuration_is_accepted(self):
        self.touch("O0.json")
        self.touch("O2.json")
        rc, out, err = run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(rc, 0, err)
        self.assertIn("2 document(s)", out)

    def test_a_document_no_configuration_accounts_for_is_refused(self):
        self.touch("O0.json")
        self.touch("O2.json")
        self.touch("O9.json")
        rc, _, err = run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(rc, 3)
        self.assertIn("O9.json", err)
        self.assertIn("no configuration in catalogue.json accounts for", err)

    def test_a_declared_configuration_with_no_document_is_refused(self):
        # The direction check-meta.py cannot see at all: it grades what is in the
        # directory, and a missing document is not in it.
        self.touch("O0.json")
        rc, _, err = run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(rc, 3)
        self.assertIn("O2.json", err)
        self.assertIn("partial one", err)

    def test_nothing_is_deleted_when_something_is_refused(self):
        self.touch("O0.json")
        self.touch("O2.json")
        self.touch("O9.json")
        run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(sorted(os.listdir(self.reports)),
                         ["O0.json", "O2.json", "O9.json"],
                         "a harness that tidies away a measurement it did not recognise can "
                         "destroy the one run that mattered")

    def test_a_missing_results_directory_is_three_and_not_zero(self):
        rc, _, err = run(ACCOUNT, os.path.join(self.tmp, "nope"), self.cat)
        self.assertEqual(rc, 3)
        self.assertIn("no report directory", err)

    def test_an_empty_results_directory_is_refused(self):
        rc, _, err = run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(rc, 3)
        self.assertIn("partial one", err)

    def test_non_json_files_are_not_documents(self):
        # check-meta.py globs *.json, so only those are the set it would grade.
        self.touch("O0.json")
        self.touch("O2.json")
        with open(os.path.join(self.reports, "notes.txt"), "w", encoding="utf-8") as fh:
            fh.write("scratch\n")
        rc, _, err = run(ACCOUNT, self.reports, self.cat)
        self.assertEqual(rc, 0, err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
