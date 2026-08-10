# Zero-Shot vs Few-Shot Experiment Summary

## What was done

A controlled comparison was conducted between zero-shot and few-shot prompting for extracting structured information from CVE descriptions.

The same 500 CVEs and the same three models were used in both conditions:

- GPT-5.5
- Claude Sonnet 4.6
- DeepSeek V4-Pro

Each model produced one result per CVE in each prompting condition, giving 1,500 outputs per condition.

The extracted fields were:

- vulnerability type
- attack vector
- affected component
- confidentiality impact
- integrity impact
- availability impact

Before comparison, the zero-shot and few-shot result files were checked and cleaned so that both contained:

- 500 CVEs per model
- 1,500 unique model-CVE pairs
- no missing pairs
- no duplicate pairs
- no invalid outputs

## Evaluation method

Exact-match accuracy was calculated for:

- attack vector
- confidentiality impact
- integrity impact
- availability impact

Vulnerability type and affected component were not treated with simple exact matching because semantically correct outputs may differ in wording or level of specificity.

Because the same CVEs were used in both conditions, the comparison was paired. For each model and field, the analysis counted:

- both prompts correct
- zero-shot correct and few-shot wrong
- zero-shot wrong and few-shot correct
- both prompts wrong

McNemar's test was used as an exploratory paired significance test.

## Main results

| Model | Zero-shot mean | Few-shot mean | Change |
|---|---:|---:|---:|
| GPT-5.5 | 65.65% | 68.10% | +2.45 points |
| Claude Sonnet 4.6 | 74.10% | 75.05% | +0.95 points |
| DeepSeek V4-Pro | 74.75% | 72.75% | -2.00 points |

Across all models and the four categorical fields:

- Zero-shot mean: 71.50%
- Few-shot mean: 71.97%
- Overall change: +0.47 percentage points

## Main interpretation

Few-shot prompting did not improve all models equally.

- GPT-5.5 benefited the most from demonstrations.
- Claude Sonnet 4.6 improved slightly.
- DeepSeek V4-Pro performed better in the zero-shot condition.

The strongest few-shot model was Claude Sonnet 4.6.

The strongest zero-shot model was DeepSeek V4-Pro.

Attack vector was generally the strongest field, while availability impact remained the weakest and most difficult field across models.

The results therefore support a model-dependent conclusion rather than the claim that few-shot prompting is universally better.

## Suggested report wording

> A paired comparison was conducted using the same 500 CVEs across zero-shot and few-shot conditions for GPT-5.5, Claude Sonnet 4.6 and DeepSeek V4-Pro. Few-shot prompting improved GPT-5.5 by 2.45 percentage points and Claude Sonnet 4.6 by 0.95 points, but reduced DeepSeek V4-Pro performance by 2.00 points. The aggregate improvement across all models and evaluated categorical fields was only 0.47 percentage points. This indicates that the effect of demonstrations was model-dependent rather than uniformly beneficial.

## Important limitation

The statistical tests were exploratory and multiple paired tests were performed. Unadjusted p-values should therefore not be presented as definitive evidence without a multiple-comparison correction.

The next stage should focus on qualitative error analysis, especially:

- availability-impact errors
- null versus None
- Network versus Adjacent Network
- examples where few-shot corrected zero-shot errors
- examples where few-shot introduced new errors
- differences in vulnerability-type wording
- broader versus narrower affected-component extraction
