import json
from typing import Dict, Any, List
from src.pii_detector import PIIDetector

class PIIEvaluator:
    """
    Automated Evaluation Suite for PII Redaction Engine.
    Evaluates Precision, Recall, F1-Score, and Accuracy across entity categories.
    """

    def __init__(self, detector: PIIDetector = None):
        self.detector = detector or PIIDetector()
        # Synthetic & Annotated Ground Truth Evaluation Set
        self.benchmark_dataset = [
            {
                "text": "Rashi Patil: John Doe, rashhi.patil@gmail.com: john.doe@example.com, Rohan Dey: Peter Parker",
                "ground_truth": [
                    {"text": "Rashi Patil", "type": "PERSON"},
                    {"text": "John Doe", "type": "PERSON"},
                    {"text": "rashhi.patil@gmail.com", "type": "EMAIL"},
                    {"text": "john.doe@example.com", "type": "EMAIL"},
                    {"text": "Rohan Dey", "type": "PERSON"},
                    {"text": "Peter Parker", "type": "PERSON"}
                ]
            },
            {
                "text": "Contact Sarthak Malvadkar at cs.connect@kshinternational.com or +91 20 45053237.",
                "ground_truth": [
                    {"text": "Sarthak Malvadkar", "type": "PERSON"},
                    {"text": "cs.connect@kshinternational.com", "type": "EMAIL"},
                    {"text": "+91 20 45053237", "type": "PHONE"}
                ]
            },
            {
                "text": "REGISTERED OFFICE: 11/3 Village Birdewadi Chakan Taluka - Khed Pune - 410 501 Maharashtra, India. CIN: U28129PN1979PLC141032.",
                "ground_truth": [
                    {"text": "11/3 Village Birdewadi Chakan Taluka - Khed Pune - 410 501 Maharashtra, India", "type": "ADDRESS"},
                    {"text": "U28129PN1979PLC141032", "type": "CIN_PAN"}
                ]
            },
            {
                "text": "PROMOTERS: KUSHAL SUBBAYYA HEGDE, PUSHPA KUSHAL HEGDE, RAJESH KUSHAL HEGDE, ROHIT KUSHAL HEGDE.",
                "ground_truth": [
                    {"text": "KUSHAL SUBBAYYA HEGDE", "type": "PERSON"},
                    {"text": "PUSHPA KUSHAL HEGDE", "type": "PERSON"},
                    {"text": "RAJESH KUSHAL HEGDE", "type": "PERSON"},
                    {"text": "ROHIT KUSHAL HEGDE", "type": "PERSON"}
                ]
            },
            {
                "text": "User IP address 192.168.1.1 accessed account on 15/01/1985 with SSN 123-45-6789.",
                "ground_truth": [
                    {"text": "192.168.1.1", "type": "IP_ADDRESS"},
                    {"text": "15/01/1985", "type": "DATE_OF_BIRTH"},
                    {"text": "123-45-6789", "type": "SSN"}
                ]
            }
        ]

    def evaluate(self) -> Dict[str, Any]:
        overall_tp = 0
        overall_fp = 0
        overall_fn = 0

        category_stats = {}

        for item in self.benchmark_dataset:
            text = item["text"]
            gt = item["ground_truth"]

            detected = self.detector.detect(text)

            # Match detected vs ground truth
            gt_matched = [False] * len(gt)
            det_matched = [False] * len(detected)

            for d_idx, d_ent in enumerate(detected):
                for g_idx, g_ent in enumerate(gt):
                    if not gt_matched[g_idx] and not det_matched[d_idx]:
                        if d_ent["text"].strip().lower() in g_ent["text"].strip().lower() or g_ent["text"].strip().lower() in d_ent["text"].strip().lower():
                            gt_matched[g_idx] = True
                            det_matched[d_idx] = True

                            t_type = g_ent["type"]
                            if t_type not in category_stats:
                                category_stats[t_type] = {"tp": 0, "fp": 0, "fn": 0}
                            category_stats[t_type]["tp"] += 1
                            overall_tp += 1
                            break

            for d_idx, d_ent in enumerate(detected):
                if not det_matched[d_idx]:
                    t_type = d_ent["type"]
                    if t_type not in category_stats:
                        category_stats[t_type] = {"tp": 0, "fp": 0, "fn": 0}
                    category_stats[t_type]["fp"] += 1
                    overall_fp += 1

            for g_idx, g_ent in enumerate(gt):
                if not gt_matched[g_idx]:
                    t_type = g_ent["type"]
                    if t_type not in category_stats:
                        category_stats[t_type] = {"tp": 0, "fp": 0, "fn": 0}
                    category_stats[t_type]["fn"] += 1
                    overall_fn += 1

        # Calculate metrics
        precision = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else 1.0
        recall = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 1.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = overall_tp / (overall_tp + overall_fp + overall_fn) if (overall_tp + overall_fp + overall_fn) > 0 else 1.0

        report = {
            "overall": {
                "tp": overall_tp,
                "fp": overall_fp,
                "fn": overall_fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "accuracy": round(accuracy, 4)
            },
            "by_category": {}
        }

        for cat, s in category_stats.items():
            tp, fp, fn = s["tp"], s["fp"], s["fn"]
            cat_prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            cat_rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
            cat_f1 = 2 * (cat_prec * cat_rec) / (cat_prec + cat_rec) if (cat_prec + cat_rec) > 0 else 0.0

            report["by_category"][cat] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": round(cat_prec, 4),
                "recall": round(cat_rec, 4),
                "f1_score": round(cat_f1, 4)
            }

        return report

if __name__ == "__main__":
    evaluator = PIIEvaluator()
    results = evaluator.evaluate()
    print(json.dumps(results, indent=2))
