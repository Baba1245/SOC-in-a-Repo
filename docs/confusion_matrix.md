## Triage confusion matrix

Evaluated on **48** manually-labelled alerts.

| true \ pred | true_positive | benign_suspicious | false_positive | support |
|---|---|---|---|---|
| **true_positive** | 12 | 1 | 0 | 13 |
| **benign_suspicious** | 2 | 16 | 6 | 24 |
| **false_positive** | 0 | 2 | 9 | 11 |

- **accuracy:** 0.7708
- **macro precision / recall / F1:** 0.7664 / 0.8026 / 0.7751

### Per class

| class | precision | recall | f1 | support |
|---|---|---|---|---|
| true_positive | 0.8571 | 0.9231 | 0.8889 | 13 |
| benign_suspicious | 0.8421 | 0.6667 | 0.7442 | 24 |
| false_positive | 0.6 | 0.8182 | 0.6923 | 11 |
