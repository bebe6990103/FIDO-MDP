#!/usr/bin/env python
# eval_and_show_terminal.py ─ 驗證 Q-table 並完整顯示於終端機

import numpy as np, pandas as pd, itertools, pathlib, json, sys
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             confusion_matrix)

# ─── 檔案路徑 ─────────────────────────────────────
Q_PATH   = pathlib.Path("q_table.npy")
VAL_PATH = pathlib.Path("validation_200.csv")
if not (Q_PATH.exists() and VAL_PATH.exists()):
    sys.exit("❌ 請確認 q_table.npy 和 validation_200.csv 與此程式同資料夾")

# ─── 1. 讀 Q-table ───────────────────────────────
Q = np.load(Q_PATH)

# ─── 2. 7 維 state2idx 映射 ──────────────────────
acc_vals, binary, tri = [0, 1, 2], [0, 1], [0, 1, 2]
all_states = [(a, up, uv, unk, rp, sign, auth)
              for a in acc_vals
              for up in binary
              for uv in binary
              for unk in binary
              for rp in binary
              for sign in tri
              for auth in tri]
if Q.shape[0] != len(all_states):
    sys.exit(f"❌ Q-table 行數 {Q.shape[0]} 與 432 不符，請檢查維度")
state2idx = {s: i for i, s in enumerate(all_states)}

# ─── 3. 讀驗證集 & 推論 ──────────────────────────
df = pd.read_csv(VAL_PATH)
cols = ["accRisk", "upFlag", "uvFlag", "hasUnknownExt",
        "rpIdMatch", "signCountRisk", "AuthenticatorRisk"]

def get_pred_q(row):
    st  = tuple(int(row[c]) for c in cols)
    idx = state2idx[st]
    q   = Q[idx]
    return q, int(np.argmax(q))

q_list, preds = zip(*df.apply(get_pred_q, axis=1))
q_arr = np.vstack(q_list)
df[["q_accept", "q_mfa", "q_reject"]] = np.round(q_arr, 2)
df["pred_action"] = preds
df["correct"] = df["action"] == df["pred_action"]

# ─── 4. 指標計算 ────────────────────────────────
acc = accuracy_score(df["action"], df["pred_action"])

# 每類 precision / recall / F1
prec, rec, f1, _ = precision_recall_fscore_support(
    df["action"], df["pred_action"], labels=[0, 1, 2], zero_division=0)

# Micro-averaged F1
_, _, micro_f1, _ = precision_recall_fscore_support(
    df["action"], df["pred_action"], average="micro", zero_division=0)

metrics = {
    "Accuracy"          : round(acc, 4),
    "Precision (0/1/2)" : np.round(prec, 3).tolist(),
    "Recall    (0/1/2)" : np.round(rec, 3).tolist(),
    "F1        (0/1/2)" : np.round(f1, 3).tolist(),
    "Macro-F1"          : round(f1.mean(), 4),
    "Micro-F1"          : round(micro_f1, 4)
}

# ─── 5. 混淆矩陣（文字顯示） ────────────────────
cm = confusion_matrix(df["action"], df["pred_action"], labels=[0, 1, 2])
print("\n=== 混淆矩陣 (Confusion Matrix) ===")
labels_txt = ["Accept", "MFA", "Reject"]
print(f"{'':10s}" + "".join(f"{l:>10s}" for l in labels_txt))
for i, row in enumerate(cm):
    print(f"{labels_txt[i]:10s}" + "".join(f"{v:10d}" for v in row))

# ─── 6. 顯示結果與指標 ──────────────────────────
pd.set_option("display.max_columns", None)
print("\n=== 驗證資料 (含 Q 值與預測) ===")
print(df.to_string(index=False))

print("\n=== 指標 ===")
print(json.dumps(metrics, indent=2, ensure_ascii=False))

# 匯出結果 CSV
df.to_csv("validation_with_preds.csv", index=False)
print("\n✅ 已另存含預測的檔案 → validation_with_preds.csv")
