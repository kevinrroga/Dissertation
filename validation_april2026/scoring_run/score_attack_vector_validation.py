import sys
sys.path.insert(0, r"C:\Users\kevin\Desktop\cve-ner-dissertation\scoring_for_attack_vector")
import score_attack_vector as sav

sav.REPORT_TXT = r"C:\Users\kevin\Desktop\cve-ner-dissertation\validation_april2026\scoring_run\score_attack_vector_validation_report.txt"
sav.REPORT_JSON = r"C:\Users\kevin\Desktop\cve-ner-dissertation\validation_april2026\scoring_run\score_attack_vector_validation_results.json"

sys.argv = ["score_attack_vector.py", r"C:\Users\kevin\Desktop\cve-ner-dissertation\validation_april2026\merging_results_validation.json"]
sav.main()
