#!/usr/bin/env python
# eval_qtable_metrics.py
# -----------------------------------------------------------
# 驗證 Q-table，輸出 Accuracy / F1 / AUC 等完整指標
# 使用範例：
#   python eval_qtable_metrics.py               # 文字輸出
#   python eval_qtable_metrics.py --plot-roc    # 另開 ROC 圖
# -----------------------------------------------------------
import argparse, sys, pathlib, json
import numpy as np, pandas as pd
from sklearn.metrics import (accuracy_score,
                             precision_recall_fscore_support,
                             confusion_matrix,
                             roc_curve, roc_auc_score)

# ---------- CLI ----------
ap = argparse.ArgumentParser()
ap.add_argument('--q',   default='q_table.npy',       help='Q-table (.npy)')
ap.add_argument('--csv', default='validation_200.csv',help='驗證資料 CSV')
ap.add_argument('--plot-roc', action='store_true',    help='顯示 ROC 曲線')
args = ap.parse_args()

Q_PATH, CSV_PATH = pathlib.Path(args.q), pathlib.Path(args.csv)
if not Q_PATH.exists() or not CSV_PATH.exists():
    sys.exit('❌ 找不到 q_table 或 CSV 驗證檔案')

# ---------- 1. 讀 Q-table ----------
Q = np.load(Q_PATH)

# ---------- 2. 建 7 維 state → idx ----------
acc_vals, binary, tri = [0,1,2], [0,1], [0,1,2]
all_states = [(a,up,uv,unk,rp,sign,auth)
              for a  in acc_vals
              for up in binary
              for uv in binary
              for unk in binary
              for rp in binary
              for sign in tri
              for auth in tri]
state2idx = {s:i for i,s in enumerate(all_states)}
if Q.shape[0] != len(all_states):
    sys.exit(f'❌ Q-table 行數 {Q.shape[0]} 與 432 不符，請檢查維度')

# ---------- 3. 讀驗證資料並推論 ----------
df  = pd.read_csv(CSV_PATH)
cols = ['accRisk','upFlag','uvFlag','hasUnknownExt',
        'rpIdMatch','signCountRisk','AuthenticatorRisk']

def infer(row):
    st   = tuple(int(row[c]) for c in cols)
    q    = Q[state2idx[st]]
    pred = int(q.argmax())
    return q, pred

q_list, preds = zip(*df.apply(infer, axis=1))
q_mat = np.vstack(q_list)
df[['q_accept','q_mfa','q_reject']] = np.round(q_mat, 2)
df['pred_action'] = preds

# ---------- 4. 分類指標 ----------
y_true, y_pred = df['action'], df['pred_action']

acc = accuracy_score(y_true, y_pred)
prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred,
                                                   labels=[0,1,2],
                                                   zero_division=0)
macro_f1 = f1.mean()

metrics = {
    'Accuracy'         : round(acc,4),
    'Precision (0/1/2)': np.round(prec,3).tolist(),
    'Recall    (0/1/2)': np.round(rec,3).tolist(),
    'F1        (0/1/2)': np.round(f1,3).tolist(),
    'Macro-F1'         : round(macro_f1,4)
}

# ---------- 5. ROC / AUC ----------
# 先把 Q 值 softmax 成 “機率感覺”
exp_q   = np.exp(q_mat)
probs   = exp_q / exp_q.sum(axis=1, keepdims=True)

y_true_oh = pd.get_dummies(y_true).reindex(columns=[0,1,2]).fillna(0).values
auc_ovr = {}
for i, cls in enumerate(['Accept','MFA','Reject']):
    auc_ovr[cls] = roc_auc_score(y_true_oh[:,i], probs[:,i])
auc_micro = roc_auc_score(y_true_oh, probs, average='micro')
auc_macro = roc_auc_score(y_true_oh, probs, average='macro')
metrics['AUC (OvR)'] = {k: round(v,3) for k,v in auc_ovr.items()}
metrics['Micro-AUC'] = round(auc_micro,3)
metrics['Macro-AUC'] = round(auc_macro,3)

# ---------- 6. 混淆矩陣文字版 ----------
cm = confusion_matrix(y_true, y_pred, labels=[0,1,2])
cm_table = '\n'.join([
    '          Pred 0  Pred 1  Pred 2',
    f'True 0   {cm[0,0]:7d} {cm[0,1]:7d} {cm[0,2]:7d}',
    f'True 1   {cm[1,0]:7d} {cm[1,1]:7d} {cm[1,2]:7d}',
    f'True 2   {cm[2,0]:7d} {cm[2,1]:7d} {cm[2,2]:7d}',
])

# ---------- 7. 輸出 ----------
pd.set_option('display.max_columns', None)
print('\n=== 指標 ===')
print(json.dumps(metrics, indent=2, ensure_ascii=False))
print('\n=== 混淆矩陣 ===')
print(cm_table)

# 如需整表存檔：
df.to_csv('validation_with_preds.csv', index=False)

# ---------- 8. (可選) 畫 ROC ----------
if args.plot_roc:
    import matplotlib.pyplot as plt
    for i, cls in enumerate(['Accept','MFA','Reject']):
        fpr, tpr, _ = roc_curve(y_true_oh[:,i], probs[:,i])
        plt.plot(fpr, tpr, label=f'{cls}  (AUC={auc_ovr[cls]:.3f})')
    plt.plot([0,1],[0,1],'k--')
    plt.xlabel('FPR'); plt.ylabel('TPR'); plt.title('ROC curves (OvR)')
    plt.legend(); plt.grid(True); plt.tight_layout(); plt.show()
