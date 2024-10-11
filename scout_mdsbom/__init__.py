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
                is_observed = result.get("suppressions") is not None
                if is_observed:
                    observed.update(result["ruleId"])
                else:
                    non_observed.update(result["ruleId"])
        return observed, non_observed


def extract_from_cyclonedx(path: str) -> Tuple[Set[str], Set[str]]:
    """Process CycloneDX file and return observed and non-observed CVEs"""
    with open(path) as f:
        data = json.load(f)
        observed, non_observed = set(), set()
        for vuln in data.get("vulnerabilities", []):
            is_observed = vuln.get("analysis", {}).get("justification") is not None
            cves = extract_cves(str(vuln))
            if is_observed:
                observed.update(cves)
            else:
                non_observed.update(cves)
        return observed, non_observed


def extract_from_csv(path: str) -> Tuple[Set[str], Set[str]]:
    """Process trivy-generated CSV file and return observed and non-observed CVEs"""
    with open(path) as f:
        observed, non_observed = set(), set()
        data = f.readlines()
        for line in data:
            is_observed = line.endswith("true\n")
            cves = extract_cves(line)
            if is_observed:
                observed.update(cves)
            else:
                non_observed.update(cves)
        return observed, non_observed


def main():
    parser = argparse.ArgumentParser(description="Generate Venn diagram from Scout and MDSBOM results")
    parser.add_argument("sarif", help="Scout generated SARIF file")
    parser.add_argument("venn", help="Venn diagram to generate")
    args = parser.parse_args()
    observed, non_observed = extract_from_sarif(args.sarif)
    total = observed.union(non_observed)
    plt.figure(figsize=(8, 8))
    venn = venn2([total, observed], ('Scout', 'Scout + Mayhem DSBOM'))
    plt.savefig(args.venn)


if __name__ == "__main__":
    main()

