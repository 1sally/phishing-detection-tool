import json
import pickle
from pathlib import Path

import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

DATASET_PATH = Path("Dataset/dataset_phishing.csv")
MODEL_PATH = Path("url_text_model.pkl")
METRICS_PATH = Path("url_text_model_metrics.json")
RANDOM_STATE = 42


def build_candidates():
    base_vectorizer = dict(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        lowercase=False,
        sublinear_tf=True,
    )

    return {
        "logreg_char_3_5": Pipeline(
            [
                ("tfidf", TfidfVectorizer(**base_vectorizer)),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=2000,
                        class_weight="balanced",
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
        "sgd_modified_huber": Pipeline(
            [
                ("tfidf", TfidfVectorizer(**base_vectorizer)),
                (
                    "clf",
                    SGDClassifier(
                        loss="modified_huber",
                        max_iter=2000,
                        tol=1e-3,
                        class_weight="balanced",
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
        "calibrated_linsvc": Pipeline(
            [
                ("tfidf", TfidfVectorizer(**base_vectorizer)),
                (
                    "clf",
                    CalibratedClassifierCV(
                        LinearSVC(
                            class_weight="balanced",
                            random_state=RANDOM_STATE,
                            dual="auto",
                        ),
                        cv=3,
                    ),
                ),
            ]
        ),
    }


def evaluate_model(model, x_train, x_test, y_train, y_test):
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    return {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "f1_phishing": round(float(f1_score(y_test, predictions, pos_label=-1)), 4),
        "precision_phishing": round(float(precision_score(y_test, predictions, pos_label=-1)), 4),
        "recall_phishing": round(float(recall_score(y_test, predictions, pos_label=-1)), 4),
    }


def main():
    df = pd.read_csv(DATASET_PATH, usecols=["url", "status"]).dropna()
    label_map = {"legitimate": 1, "phishing": -1}
    df["label"] = df["status"].map(label_map)
    df = df[df["label"].isin(label_map.values())].copy()

    x_train, x_test, y_train, y_test = train_test_split(
        df["url"],
        df["label"],
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=df["label"],
    )

    candidates = build_candidates()
    evaluation = {}
    best_name = None
    best_metrics = None

    for name, model in candidates.items():
        metrics = evaluate_model(model, x_train, x_test, y_train, y_test)
        evaluation[name] = metrics

        if best_metrics is None or (
            metrics["f1_phishing"],
            metrics["accuracy"],
        ) > (
            best_metrics["f1_phishing"],
            best_metrics["accuracy"],
        ):
            best_name = name
            best_metrics = metrics

    final_model = build_candidates()[best_name]
    final_model.fit(df["url"], df["label"])

    with MODEL_PATH.open("wb") as model_file:
        pickle.dump(final_model, model_file)

    output = {
        "dataset_rows": int(len(df)),
        "label_counts": {
            "legitimate": int((df["label"] == 1).sum()),
            "phishing": int((df["label"] == -1).sum()),
        },
        "best_model": best_name,
        "best_metrics": best_metrics,
        "all_models": evaluation,
        "model_path": str(MODEL_PATH),
    }

    METRICS_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
