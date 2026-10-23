import sys, os
sys.path.insert(0, r"C:\Users\kevin\Desktop\cve-ner-dissertation\scoring_for_affected_component")
import score_affected_component as sac

sac.RESULTS_PATH = r"C:\Users\kevin\Desktop\cve-ner-dissertation\validation_april2026\merging_results_validation.json"
sac.OUT_DIR = r"C:\Users\kevin\Desktop\cve-ner-dissertation\validation_april2026\scoring_run\affected_component_outputs"
os.makedirs(sac.OUT_DIR, exist_ok=True)
sac.main()
