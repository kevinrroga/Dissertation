"""
fix_affected_components.py
============================
Standalone fix for ONE thing: the CPE escaped-colon parsing bug found during
the Day 3 spot-check (via verify_sample.py's raw evidence). Does NOT touch
dataset_multiple_cwes.py -- this is deliberately separate so the fix can be
read and understood on its own before being folded into the main pipeline.

THE BUG, BRIEFLY: CPE 2.3 strings use ':' to separate fields, but some
product names contain a literal colon too (e.g. Perl's "Archive::Tar").
NVD escapes those with a backslash ("\\:") to mark them as part of the name,
not a separator. The old code split on every colon regardless of escaping,
so an escaped colon shifted every field after it out of position --
producing garbage vendor/product names for those specific records.

THE FIX: split only on colons that are NOT preceded by a backslash, then
remove the backslash from any escaped character left in each field.

WHAT THIS SCRIPT DOES -- AND DOESN'T:
  - Reads your EXISTING dataset. Makes ZERO calls to the NVD API -- the raw
    CPE strings were never corrupted (only the derived display name was),
    so the fix can be applied entirely offline from data you already have.
  - Recomputes affected_components for every record from affected_cpes_raw.
  - Prints every record the fix actually changes, old value next to new,
    so you can see precisely what was wrong before trusting the result.
  - Writes the corrected records to a NEW file. Your original dataset file
    is opened read-only and is never modified.

USAGE:
    python fix_affected_components.py [input.json] [output.json]

    Both optional. Defaults: dataset_minus_rejected.json -> dataset_cpe_fixed.json
"""

import json
import re
import sys

DEFAULT_INPUT = "dataset_minus_rejected.json"
DEFAULT_OUTPUT = "dataset_cpe_fixed.json"


def parse_cpe_vendor_product(criteria):
    """
    The actual fix. Replaces the old `criteria.split(":")`.

    Step 1: split on colons, but skip any colon that has a backslash
    directly before it -- those are escaped, meaning "this is part of the
    name, not a field separator".
    Step 2: strip the backslash from any remaining escaped character in
    each field, so the result is clean, readable text.
    """
    fields = re.split(r'(?<!\\):', criteria)
    fields = [re.sub(r'\\(.)', r'\1', f) for f in fields]
    if len(fields) >= 5:
        vendor = fields[3].replace('_', ' ')
        product = fields[4].replace('_', ' ')
        return f"{vendor} {product}"
    return None


def recompute_affected_components(record):
    """Rebuilds affected_components from the untouched affected_cpes_raw,
    using the fixed parser instead of the old broken one."""
    components = []
    for criteria in record.get("affected_cpes_raw", []):
        pair = parse_cpe_vendor_product(criteria)
        if pair and pair not in components:
            components.append(pair)
    return components


def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    output_file = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT

    with open(input_file, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    changed_count = 0
    fixed_dataset = []

    for record in dataset:
        # Only CPE-sourced records ever went through the buggy parsing path;
        # leave anything else exactly as it was.
        if record.get("affected_component_source") != "cpe":
            fixed_dataset.append(record)
            continue

        old_components = record.get("affected_components", [])
        new_components = recompute_affected_components(record)

        new_record = dict(record)
        new_record["affected_components"] = new_components
        fixed_dataset.append(new_record)

        if new_components != old_components:
            changed_count += 1
            print("=" * 70)
            print(record["cve_id"])
            print("=" * 70)
            print(f"  WAS:  {old_components}")
            print(f"  NOW:  {new_components}")
            print()

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(fixed_dataset, f, indent=4)

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total records checked:                      {len(dataset)}")
    print(f"Records with corrected affected_components:  {changed_count}")
    print(f"Original file (untouched):  {input_file}")
    print(f"Corrected file (new):       {output_file}")


if __name__ == "__main__":
    main()