"""GitHub workflows (.github/workflows): rules the YAML check of test-quick.sh doesn't see."""
import glob
import os

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_cancelling_concurrency_only_on_jobs_that_run():
    # workflow-level concurrency is taken by every run, also one whose jobs are all skipped by their `if:` – with
    # cancel-in-progress such a run cancels the one that would have done the work (pr-hints: a title edit)
    for p in glob.glob(os.path.join(ROOT, ".github/workflows/*.yml")):
        wf = yaml.safe_load(open(p))
        conc = wf.get("concurrency")
        if isinstance(conc, dict) and conc.get("cancel-in-progress"):
            skippable = [n for n, j in wf.get("jobs", {}).items() if "if" in j]
            assert not skippable, f"{os.path.basename(p)}: move concurrency to the jobs {skippable}"
