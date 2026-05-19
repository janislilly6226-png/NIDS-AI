"""
=============================================================
 NIDS - ML Model Training Script
 Trains XGBoost + Random Forest on CICIDS 2017/2018 dataset
 Saves models ready for nids_dashboard.py to load

 Usage:
   python nids_ml_model.py                  (train on full dataset)
   python nids_ml_model.py --sample         (quick test on 5000 rows)
   python nids_ml_model.py --combine        (merge multiple CSVs first)
   python nids_ml_model.py --evaluate       (evaluate saved model only)
=============================================================
"""

import os, sys, time, glob, warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')   # no display needed
import matplotlib.pyplot as plt
warnings.filterwarnings('ignore')

from sklearn.model_selection  import train_test_split, cross_val_score
from sklearn.preprocessing    import LabelEncoder, StandardScaler
from sklearn.ensemble         import RandomForestClassifier
from sklearn.metrics          import (classification_report,
                                      confusion_matrix,
                                      accuracy_score,
                                      f1_score)
from xgboost import XGBClassifier

# 
# CONFIG
# 

DATASET_PATH  = 'data/cicids2017.csv'   # change if your file has different name
MODELS_DIR    = 'models'
REPORTS_DIR   = 'reports'
TEST_SIZE     = 0.20      # 80% train, 20% test
RANDOM_STATE  = 42
SAMPLE_SIZE   = 5000      # used with --sample flag

# Columns to drop (not useful for ML)
DROP_COLS = [
    'Flow ID', 'Source IP', 'Destination IP',
    'Source Port', 'Timestamp',
]

# 
# STEP 1 — COMBINE MULTIPLE CSVs (optional)
# If you downloaded multiple CICIDS files, this merges them
# 

def combine_csvs():
    """Merge all CSV files in /data/ into one big dataset."""
    files = glob.glob('data/*.csv')
    if not files:
        print('[!] No CSV files found in data/ folder')
        return

    print(f'[*] Found {len(files)} CSV files:')
    for f in files: print(f'    - {f}')

    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f'    Loaded {f}: {df.shape[0]:,} rows')
        except Exception as e:
            print(f'    [!] Failed to load {f}: {e}')

    combined = pd.concat(dfs, ignore_index=True)
    combined.to_csv(DATASET_PATH, index=False)
    print(f'\n[+] Combined dataset saved: {combined.shape[0]:,} rows → {DATASET_PATH}')


# 
# STEP 2 — LOAD DATASET
# 

def load_dataset(sample=False):
    print('\n' + '='*55)
    print(' STEP 1: Loading Dataset')
    print('='*55)

    if not os.path.exists(DATASET_PATH):
        print(f'[!] Dataset not found at: {DATASET_PATH}')
        print('\n    Options:')
        print('    1. Download from: https://www.unb.ca/cic/datasets/ids-2017.html')
        print('    2. Place CSV file in data/ folder')
        print('    3. Use sample: python nids_ml_model.py --sample')
        sys.exit(1)

    print(f'[*] Loading {DATASET_PATH}...')
    t0 = time.time()
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f'[+] Loaded in {time.time()-t0:.1f}s')

    # Strip whitespace from column names (CICIDS has this issue)
    df.columns = df.columns.str.strip()

    print(f'[+] Shape: {df.shape[0]:,} rows × {df.shape[1]} columns')

    # Check Label column exists
    if 'Label' not in df.columns:
        # Try common alternatives
        for alt in ['label','LABEL','Class','class']:
            if alt in df.columns:
                df.rename(columns={alt:'Label'}, inplace=True)
                break
        else:
            print('[!] No "Label" column found in dataset!')
            print(f'    Columns found: {list(df.columns[:10])}...')
            sys.exit(1)

    # Show class distribution
    print(f'\n[+] Label distribution:')
    counts = df['Label'].value_counts()
    total  = len(df)
    for label, count in counts.items():
        bar = '' * min(int(count/total*40), 40)
        print(f'    {label:<25} {count:>7,}  {bar}')

    # Sample if requested
    if sample:
        print(f'\n[*] Sampling {SAMPLE_SIZE:,} rows for quick test...')
        # Stratified sample to keep all classes
        df = df.groupby('Label', group_keys=False).apply(
            lambda x: x.sample(min(len(x), SAMPLE_SIZE//df['Label'].nunique()),
                               random_state=RANDOM_STATE)
        ).reset_index(drop=True)
        print(f'[+] Sample shape: {df.shape[0]:,} rows')

    return df


# 
# STEP 3 — PREPROCESS
# 

def preprocess(df):
    print('\n' + '='*55)
    print(' STEP 2: Preprocessing')
    print('='*55)

    original_rows = len(df)

    # Drop ID columns
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    df = df.drop(columns=cols_to_drop)
    print(f'[+] Dropped {len(cols_to_drop)} non-feature columns')

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Show missing value count before dropping
    null_count = df.isnull().sum().sum()
    if null_count > 0:
        print(f'[*] Found {null_count:,} missing/infinite values — removing rows')

    df.dropna(inplace=True)
    removed = original_rows - len(df)
    if removed > 0:
        print(f'[+] Removed {removed:,} bad rows ({removed/original_rows*100:.1f}%)')

    print(f'[+] Clean dataset: {len(df):,} rows')

    # Separate features and target
    X = df.drop(columns=['Label'])
    y = df['Label']

    # Keep only numeric columns
    X = X.select_dtypes(include=[np.number])
    print(f'[+] Features: {X.shape[1]} numeric columns')

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f'[+] Classes encoded: {list(le.classes_)}')

    # Scale features
    print('[*] Scaling features...')
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split — stratified to keep class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y_encoded,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y_encoded
    )

    print(f'[+] Train: {X_train.shape[0]:,} rows  |  Test: {X_test.shape[0]:,} rows')

    return X_train, X_test, y_train, y_test, scaler, le, list(X.columns)


# 
# STEP 4 — TRAIN MODELS
# 

def train_random_forest(X_train, y_train, n_classes):
    print('\n' + '='*55)
    print(' STEP 3a: Training Random Forest')
    print('='*55)
    t0 = time.time()

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,          # use all CPU cores
        random_state=RANDOM_STATE,
        verbose=0,
    )
    rf.fit(X_train, y_train)

    elapsed = time.time() - t0
    print(f'[+] Random Forest trained in {elapsed:.1f}s')
    print(f'    Trees: {rf.n_estimators} | Depth: {rf.max_depth}')
    return rf


def train_xgboost(X_train, y_train, n_classes):
    print('\n' + '='*55)
    print(' STEP 3b: Training XGBoost')
    print('='*55)
    t0 = time.time()

    xgb = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='mlogloss' if n_classes > 2 else 'logloss',
        use_label_encoder=False,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        verbosity=0,
    )
    xgb.fit(
        X_train, y_train,
        verbose=False,
    )

    elapsed = time.time() - t0
    print(f'[+] XGBoost trained in {elapsed:.1f}s')
    print(f'    Trees: {xgb.n_estimators} | Depth: {xgb.max_depth} | LR: {xgb.learning_rate}')
    return xgb


# 
# STEP 5 — EVALUATE
# 

def evaluate(model, X_test, y_test, le, model_name):
    print('\n' + '='*55)
    print(f' STEP 4: Evaluating {model_name}')
    print('='*55)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred) * 100
    f1  = f1_score(y_test, y_pred, average='weighted') * 100

    print(f'\n  Accuracy  : {acc:.2f}%')
    print(f'  F1 Score  : {f1:.2f}%')

    # Per-class report
    print(f'\n  Per-Class Report:')
    report = classification_report(
        y_test, y_pred,
        target_names=le.classes_,
        output_dict=True
    )
    for cls in le.classes_:
        r = report.get(cls, {})
        prec = r.get('precision', 0) * 100
        rec  = r.get('recall', 0)    * 100
        f1c  = r.get('f1-score', 0)  * 100
        sup  = int(r.get('support', 0))
        bar  = '' * int(f1c/5)
        print(f'  {cls:<20} P:{prec:5.1f}%  R:{rec:5.1f}%  F1:{f1c:5.1f}%  [{sup:>5} samples]  {bar}')

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f'\n  Confusion Matrix ({model_name}):')
    print(f'  Classes: {list(le.classes_)}')
    for i, row in enumerate(cm):
        print(f'  {le.classes_[i]:<20} {list(row)}')

    return acc, f1, y_pred


# 
# STEP 6 — FEATURE IMPORTANCE
# 

def show_feature_importance(model, feature_names, model_name, top_n=15):
    print(f'\n  Top {top_n} Most Important Features ({model_name}):')

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    else:
        return

    indices = np.argsort(importances)[::-1][:top_n]
    max_imp  = importances[indices[0]]

    for rank, idx in enumerate(indices, 1):
        name = feature_names[idx] if idx < len(feature_names) else f'feature_{idx}'
        imp  = importances[idx]
        bar  = '' * int(imp/max_imp * 30)
        print(f'  {rank:>2}. {name:<35} {bar} ({imp:.4f})')


# 
# STEP 7 — SAVE MODELS
# 

def save_models(rf, xgb, scaler, le, feature_names, rf_acc, xgb_acc):
    print('\n' + '='*55)
    print(' STEP 5: Saving Models')
    print('='*55)

    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(rf,            f'{MODELS_DIR}/random_forest.pkl')
    joblib.dump(xgb,           f'{MODELS_DIR}/xgboost.pkl')
    joblib.dump(scaler,        f'{MODELS_DIR}/scaler.pkl')
    joblib.dump(le,            f'{MODELS_DIR}/label_encoder.pkl')
    joblib.dump(feature_names, f'{MODELS_DIR}/feature_names.pkl')

    # Save summary
    summary = {
        'trained_at'     : time.strftime('%Y-%m-%d %H:%M:%S'),
        'random_forest_accuracy': round(rf_acc, 2),
        'xgboost_accuracy'      : round(xgb_acc, 2),
        'best_model'     : 'xgboost' if xgb_acc >= rf_acc else 'random_forest',
        'classes'        : list(le.classes_),
        'n_features'     : len(feature_names),
    }
    import json
    with open(f'{MODELS_DIR}/summary.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print(f'[+] Saved:')
    for fname in ['random_forest.pkl','xgboost.pkl','scaler.pkl','label_encoder.pkl','feature_names.pkl','summary.json']:
        size = os.path.getsize(f'{MODELS_DIR}/{fname}') / 1024
        print(f'    {MODELS_DIR}/{fname}  ({size:.1f} KB)')

    print(f'\n[+] Best model: {summary["best_model"].upper()}')
    print(f'    → nids_dashboard.py will load this automatically')


# 
# STEP 8 — SAVE EVALUATION PLOTS
# 

def save_plots(rf, xgb, X_test, y_test, le, feature_names):
    os.makedirs(REPORTS_DIR, exist_ok=True)

    #  Plot 1: Confusion Matrix for XGBoost 
    y_pred = xgb.predict(X_test)
    cm     = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8,6))
    fig.patch.set_facecolor('#060d14')
    ax.set_facecolor('#0b1929')
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    plt.colorbar(im, ax=ax)
    ax.set_xticks(range(len(le.classes_)))
    ax.set_yticks(range(len(le.classes_)))
    ax.set_xticklabels(le.classes_, rotation=45, ha='right', color='white', fontsize=8)
    ax.set_yticklabels(le.classes_, color='white', fontsize=8)
    ax.set_title('XGBoost Confusion Matrix', color='#00c8ff', fontsize=12, pad=15)
    ax.set_xlabel('Predicted', color='white')
    ax.set_ylabel('Actual', color='white')
    for i in range(len(le.classes_)):
        for j in range(len(le.classes_)):
            ax.text(j,i,str(cm[i,j]),ha='center',va='center',
                    color='white' if cm[i,j]<cm.max()/2 else 'black', fontsize=8)
    plt.tight_layout()
    plt.savefig(f'{REPORTS_DIR}/confusion_matrix.png', dpi=120, facecolor='#060d14')
    plt.close()
    print(f'[+] Saved: {REPORTS_DIR}/confusion_matrix.png')

    #  Plot 2: Feature Importance 
    importances = xgb.feature_importances_
    top_idx     = np.argsort(importances)[::-1][:15]
    top_names   = [feature_names[i] if i<len(feature_names) else f'f{i}' for i in top_idx]
    top_imp     = importances[top_idx]

    fig, ax = plt.subplots(figsize=(10,6))
    fig.patch.set_facecolor('#060d14')
    ax.set_facecolor('#0b1929')
    bars = ax.barh(range(len(top_names)), top_imp[::-1], color='#00c8ff', alpha=0.8)
    ax.set_yticks(range(len(top_names)))
    ax.set_yticklabels(top_names[::-1], color='white', fontsize=9)
    ax.set_xlabel('Importance Score', color='white')
    ax.set_title('Top 15 Feature Importances (XGBoost)', color='#00c8ff', fontsize=12, pad=15)
    ax.tick_params(colors='white')
    for spine in ax.spines.values(): spine.set_edgecolor('#112840')
    plt.tight_layout()
    plt.savefig(f'{REPORTS_DIR}/feature_importance.png', dpi=120, facecolor='#060d14')
    plt.close()
    print(f'[+] Saved: {REPORTS_DIR}/feature_importance.png')

    #  Plot 3: Model Comparison 
    rf_pred  = rf.predict(X_test)
    xgb_pred = xgb.predict(X_test)
    metrics  = ['Accuracy','F1 Score']
    rf_scores  = [accuracy_score(y_test,rf_pred)*100,  f1_score(y_test,rf_pred,average='weighted')*100]
    xgb_scores = [accuracy_score(y_test,xgb_pred)*100, f1_score(y_test,xgb_pred,average='weighted')*100]

    x   = np.arange(len(metrics))
    w   = 0.3
    fig, ax = plt.subplots(figsize=(7,5))
    fig.patch.set_facecolor('#060d14')
    ax.set_facecolor('#0b1929')
    ax.bar(x-w/2, rf_scores,  w, label='Random Forest', color='#00e887', alpha=0.85)
    ax.bar(x+w/2, xgb_scores, w, label='XGBoost',       color='#00c8ff', alpha=0.85)
    ax.set_ylim(80, 102)
    ax.set_xticks(x); ax.set_xticklabels(metrics, color='white', fontsize=11)
    ax.set_ylabel('Score (%)', color='white')
    ax.set_title('Model Comparison', color='#00c8ff', fontsize=13, pad=15)
    ax.legend(facecolor='#0b1929', edgecolor='#112840', labelcolor='white')
    ax.tick_params(colors='white')
    for spine in ax.spines.values(): spine.set_edgecolor('#112840')
    for i,v in enumerate(rf_scores):  ax.text(i-w/2, v+0.3, f'{v:.1f}%', ha='center', color='white', fontsize=9)
    for i,v in enumerate(xgb_scores): ax.text(i+w/2, v+0.3, f'{v:.1f}%', ha='center', color='white', fontsize=9)
    plt.tight_layout()
    plt.savefig(f'{REPORTS_DIR}/model_comparison.png', dpi=120, facecolor='#060d14')
    plt.close()
    print(f'[+] Saved: {REPORTS_DIR}/model_comparison.png')


# 
# EVALUATE SAVED MODEL (no retraining)
# 

def evaluate_saved():
    print('[*] Loading saved models for evaluation...')
    try:
        xgb    = joblib.load(f'{MODELS_DIR}/xgboost.pkl')
        scaler = joblib.load(f'{MODELS_DIR}/scaler.pkl')
        le     = joblib.load(f'{MODELS_DIR}/label_encoder.pkl')
    except FileNotFoundError:
        print('[!] No saved models found. Train first: python nids_ml_model.py')
        sys.exit(1)

    import json
    with open(f'{MODELS_DIR}/summary.json') as f:
        summary = json.load(f)

    print(f'\n Model Summary:')
    print(f'  Trained at     : {summary["trained_at"]}')
    print(f'  XGBoost Acc    : {summary["xgboost_accuracy"]}%')
    print(f'  RF Accuracy    : {summary["random_forest_accuracy"]}%')
    print(f'  Best Model     : {summary["best_model"].upper()}')
    print(f'  Classes        : {summary["classes"]}')
    print(f'  Features       : {summary["n_features"]}')
    print(f'\n[+] Model is ready. Run: sudo venv/bin/python nids_dashboard.py eth0')


# 
# PREDICT SINGLE SAMPLE (test the model)
# 

def predict_sample():
    """Quick test: predict on one sample from test set."""
    print('\n[*] Testing prediction on a sample flow...')
    try:
        xgb    = joblib.load(f'{MODELS_DIR}/xgboost.pkl')
        scaler = joblib.load(f'{MODELS_DIR}/scaler.pkl')
        le     = joblib.load(f'{MODELS_DIR}/label_encoder.pkl')
        fnames = joblib.load(f'{MODELS_DIR}/feature_names.pkl')
    except:
        print('[!] Run training first')
        return

    # Make a fake DDoS-like flow
    sample = {f: 0 for f in fnames}
    sample.update({
        'Total Fwd Packets'     : 2000,
        'Total Backward Packets': 0,
        'Flow Packets/s'        : 5000,
        'Flow Bytes/s'          : 200000,
        'SYN Flag Count'        : 500,
        'ACK Flag Count'        : 0,
        'Fwd Packet Length Mean': 60,
    })

    df   = pd.DataFrame([sample])[fnames]
    X    = scaler.transform(df)
    pred = xgb.predict(X)[0]
    prob = xgb.predict_proba(X)[0]
    label= le.inverse_transform([pred])[0]
    conf = prob[pred]*100

    print(f'\n  Input: High packet rate, many SYNs, no responses')
    print(f'  Prediction : {label}')
    print(f'  Confidence : {conf:.1f}%')
    print(f'  All probs  :')
    for cls, p in zip(le.classes_, prob):
        bar = '' * int(p*30)
        print(f'    {cls:<20} {bar} {p*100:.1f}%')


# 
# MAIN
# 

if __name__ == '__main__':

    #  Handle flags 
    if '--combine' in sys.argv:
        combine_csvs()
        sys.exit(0)

    if '--evaluate' in sys.argv:
        evaluate_saved()
        sys.exit(0)

    sample_mode = '--sample' in sys.argv

    print('\n' + ''*55)
    print('  NIDS ML MODEL TRAINING')
    print('  East Africa Network Intrusion Detection System')
    print(''*55)
    if sample_mode:
        print('    SAMPLE MODE — quick test only')
        print('     Remove --sample for full training\n')

    start_total = time.time()

    #  Run pipeline 
    df = load_dataset(sample=sample_mode)

    X_train, X_test, y_train, y_test, scaler, le, feature_names = preprocess(df)

    n_classes = len(le.classes_)

    rf  = train_random_forest(X_train, y_train, n_classes)
    xgb = train_xgboost(X_train, y_train, n_classes)

    rf_acc,  rf_f1,  _ = evaluate(rf,  X_test, y_test, le, 'Random Forest')
    xgb_acc, xgb_f1, _ = evaluate(xgb, X_test, y_test, le, 'XGBoost')

    show_feature_importance(rf,  feature_names, 'Random Forest')
    show_feature_importance(xgb, feature_names, 'XGBoost')

    save_models(rf, xgb, scaler, le, feature_names, rf_acc, xgb_acc)

    print('\n[*] Saving evaluation plots...')
    try:
        save_plots(rf, xgb, X_test, y_test, le, feature_names)
    except Exception as e:
        print(f'[!] Plot error (non-critical): {e}')

    predict_sample()

    total = time.time() - start_total
    print('\n' + ''*55)
    print(f'    TRAINING COMPLETE in {total/60:.1f} minutes')
    print(f'  Random Forest : {rf_acc:.2f}%')
    print(f'  XGBoost       : {xgb_acc:.2f}%')
    print(f'  Best model    : {"XGBoost" if xgb_acc>=rf_acc else "Random Forest"}')
    print(f'\n  Next step:')
    print(f'  sudo venv/bin/python nids_dashboard.py eth0')
    print(''*55 + '\n')
