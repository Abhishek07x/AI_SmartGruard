"""SmartGuard — ML Model Training (Kaggle RBA features)"""
import pickle, json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

BASE   = Path(__file__).parent.parent
DATA   = BASE / 'data' / 'smartguard_dataset.csv'
MDIR   = BASE / 'models'
MDIR.mkdir(exist_ok=True)

print("📊 Loading dataset...")
df = pd.read_csv(DATA)
print(f"   {len(df):,} events, {len(df.columns)} columns")

le_country = LabelEncoder()
le_device  = LabelEncoder()
le_browser = LabelEncoder()
le_os      = LabelEncoder()

df['ce'] = le_country.fit_transform(df['country'].fillna('Unknown'))
df['de'] = le_device.fit_transform(df.get('device_cat', df.get('device_type', pd.Series(['Desktop']*len(df)))).fillna('Desktop'))
df['be'] = le_browser.fit_transform(df.get('browser_clean', df.get('browser', pd.Series(['Chrome']*len(df)))).fillna('Chrome'))
df['oe'] = le_os.fit_transform(df.get('os', pd.Series(['Windows 10']*len(df))).fillna('Windows 10'))

FEATURES = ['ce','de','be','oe','rtt_ms','is_attack_ip','hour_of_day']
FEATURES = [f for f in FEATURES if f in df.columns]

X = df[FEATURES].fillna(0)
y = (df['risk_score'] >= 70).astype(int)

X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("🤖 Training GradientBoostingClassifier...")
model = GradientBoostingClassifier(n_estimators=200, max_depth=5, learning_rate=0.08,
                                    subsample=0.8, min_samples_leaf=10, random_state=42)
model.fit(X_tr, y_tr)

y_pred = model.predict(X_te)
y_prob = model.predict_proba(X_te)[:, 1]
auc = roc_auc_score(y_te, y_prob)
print(classification_report(y_te, y_pred, target_names=['Normal','High-Risk']))
print(f"AUC-ROC: {auc:.4f}")

imps = dict(zip(FEATURES, model.feature_importances_))
feat_labels = {'ce':'Country','de':'Device Type','be':'Browser','oe':'OS',
               'rtt_ms':'Network RTT','is_attack_ip':'Attack IP Flag','hour_of_day':'Hour of Day'}

pickle.dump(model,      open(MDIR/'model.pkl','wb'))
pickle.dump(le_country, open(MDIR/'le_country.pkl','wb'))
pickle.dump(le_device,  open(MDIR/'le_device.pkl','wb'))
pickle.dump(le_browser, open(MDIR/'le_browser.pkl','wb'))
pickle.dump(le_os,      open(MDIR/'le_os.pkl','wb'))

schema = {
    'features': FEATURES,
    'feature_labels': feat_labels,
    'known_countries': list(le_country.classes_),
    'known_devices': list(le_device.classes_),
    'known_browsers': list(le_browser.classes_),
    'known_os': list(le_os.classes_),
    'auc_roc': round(auc, 4),
    'trained_on': len(df),
    'dataset_source': 'Kaggle RBA Dataset',
}
json.dump(schema, open(MDIR/'schema.json','w'), indent=2)
json.dump({feat_labels.get(k,k): round(float(v),6) for k,v in imps.items()},
          open(MDIR/'importances.json','w'), indent=2)

print(f"\n✅ Model saved → models/ (AUC={auc:.4f})")
