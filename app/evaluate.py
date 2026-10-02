import json
from pathlib import Path
from app.firewall import PromptInjectionFirewall
from app.models import ScanRequest

def main():
    dataset = json.loads(Path("data/evaluation_dataset.json").read_text(encoding="utf-8"))
    firewall = PromptInjectionFirewall()

    total = len(dataset)
    correct = 0
    tp = fp = fn = 0

    for item in dataset:
        result = firewall.scan(ScanRequest(
            content=item["text"],
            source_type=item.get("source_type", "user_message"),
            external_content=item.get("external_content", False),
        ))
        predicted_malicious = result.decision != "ALLOW"
        actual_malicious = item["label"] == "malicious"

        if predicted_malicious == actual_malicious:
            correct += 1
        if predicted_malicious and actual_malicious:
            tp += 1
        elif predicted_malicious and not actual_malicious:
            fp += 1
        elif not predicted_malicious and actual_malicious:
            fn += 1

    accuracy = correct / total if total else 0
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    print(f"Samples:   {total}")
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"TP={tp} FP={fp} FN={fn}")

if __name__ == "__main__":
    main()
