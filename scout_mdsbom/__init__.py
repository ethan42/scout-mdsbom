#!/usr/bin/env python3

import argparse
import json
import matplotlib.pyplot as plt

from matplotlib_venn import venn2
from typing import Set, Tuple


def extract_from_sarif(path: str) -> Tuple[Set[str], Set[str]]:
    """Process SARIF file and return observed and non-observed CVEs"""
    with open(path) as f:
        data = json.load(f)
        observed, non_observed = set(), set()
        for run in data["runs"]:
            for result in run["results"]:
                is_not_observed = result.get("suppressions") is not None
                print(result["ruleId"], result.get("suppressions") is not None)
                if is_not_observed:
                    non_observed.add(result["ruleId"])
                else:
                    observed.add(result["ruleId"])
        return observed, non_observed


def main():
    parser = argparse.ArgumentParser(description="Generate Venn diagram from Scout and MDSBOM results")
    parser.add_argument("sarif", help="Scout generated SARIF file")
    parser.add_argument("venn", help="Venn diagram to generate")
    args = parser.parse_args()
    observed, non_observed = extract_from_sarif(args.sarif)
    total = observed | non_observed
    plt.figure(figsize=(8, 8))
    venn = venn2([total, observed], ('Scout', 'Scout + Mayhem DSBOM'))
    plt.savefig(args.venn)


if __name__ == "__main__":
    main()

