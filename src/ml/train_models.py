import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

def train():
    df = pd.read_csv("data/sample/flow_dataset.csv")
    
    features = [
        "destination_port", "duration", "packet_count", 
        "byte_count", "packets_per_sec", "bytes_per_sec", "protocol_tcp"
    ]
    
    X = df[features]
    y = df["label"]
    
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    print("Training XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="mlogloss",
        random_state=42
    )
    xgb.fit(X_train, y_train)
    
    y_pred = xgb.predict(X_test)
    print("\n--- Model Evaluation (XGBoost) ---")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    print("Training Isolation Forest on Normal baseline...")
    normal_indices = (y_train == label_encoder.transform(["Normal"])[0])
    X_normal_train = X_train[normal_indices]
    
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=42
    )
    iso_forest.fit(X_normal_train)
    joblib.dump(xgb, "models/xgboost_model.pkl")
    joblib.dump(iso_forest, "models/isolation_forest.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    joblib.dump(label_encoder, "models/label_encoder.pkl")
    print("\n[+] All models and artifacts saved to models/")

if __name__ == "__main__":
    train()