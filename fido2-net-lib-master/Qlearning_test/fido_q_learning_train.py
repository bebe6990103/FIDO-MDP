#!/usr/bin/env python
# fido_q_learning_train_offline_fixed_eps.py  (ε 固定版, Episodes vs Accuracy)

import numpy as np, random, itertools, pandas as pd, time
from collections import Counter
from pathlib import Path
import matplotlib.pyplot as plt

# ───── 0. Hyper-params ──────────────────────────
ALPHA   = 0.3
GAMMA   = 0.9
LAMBDA  = 3
EPISODES, MAX_STEPS = 15_000, 75
EPS_FIXED   = 0.2               # 固定 ε
EVAL_EVERY  = 300               # 每 300 回合評估一次驗證集
rng = random.Random(42)

# ───── 0b. 讀入驗證集 ──────────────────────────
VAL_FILE = Path("validation_400.csv")
if not VAL_FILE.exists():
    raise FileNotFoundError("⚠ 找不到 validation_200.csv，請確認路徑")
val_df  = pd.read_csv(VAL_FILE)
VAL_COLS = ["accRisk","upFlag","uvFlag","hasUnknownExt",
            "rpIdMatch","signCountRisk","AuthenticatorRisk"]

# ───── 1. State space ───────────────────────────
acc_vals = [0,1,2]; binary=[0,1]; tri=[0,1,2]
all_states = list(itertools.product(acc_vals,binary,binary,
                                    binary,binary,tri,tri))
state2idx  = {s:i for i,s in enumerate(all_states)}

# ───── 2. Actions ───────────────────────────────
A_ACCEPT, A_MFA, A_REJECT = 0,1,2
actions = [A_ACCEPT, A_MFA, A_REJECT]

# ───── 3. accRisk transition ────────────────────
P_accept = np.array([[0.70,0.20,0.10],
                     [0.30,0.50,0.20],
                     [0.20,0.30,0.50]])
P_mfa    = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.20,0.30,0.50]])
P_reject = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.10,0.20,0.70]])
P_dict   = {A_ACCEPT:P_accept, A_MFA:P_mfa, A_REJECT:P_reject}
def next_acc_risk(cur, act): return rng.choices([0,1,2], P_dict[act][cur])[0]

# ───── 4. Risk → Reward (Favor ACCEPT, tame REJECT) ──────────
W_ACC, W_UP, W_UV, W_UNK = 4.0, 0.30, 0.30, 2.0
W_RP,  W_SIGN, W_AUTH    = 1.2, 2.5, 2.7     # ↓ 再降 0.3

LOW_TH, MID_TH = 5, 9

# ---------- 低風險 ----------
BONUS_ACCEPT_LOW     = 45      # ↑ 再加
MFA_LOW_REWARD       = 20      # 轉為正向獎勵
REJECT_LOW_PENALTY   = -80     # 最重罰

# ---------- 中風險 ----------
ACCEPT_MID_REWARD    = 35      # ↑
MFA_MID_REWARD       = 18      # 正但次之
REJECT_MID_PENALTY   = -40     # 更負

# ---------- 高風險 ----------
PENALTY_ACCEPT_HIGH  = -50
MFA_HIGH_REWARD      = 12
REJECT_HIGH_REWARD   = 20      # ↓ 再降 8

def risk_score(s):
    acc, up, uv, unk, rp, sign, auth = s
    return (W_ACC*acc + W_UP*(1-up) + W_UV*(1-uv) +
            W_UNK*unk + W_RP*(1-rp) + W_SIGN*sign + W_AUTH*auth)

def reward_fn(s, a):
    r = risk_score(s)

    # --- Accept ---
    if a == A_ACCEPT:
        if r <= LOW_TH: return BONUS_ACCEPT_LOW
        if r <= MID_TH: return ACCEPT_MID_REWARD
        return PENALTY_ACCEPT_HIGH

    # --- MFA ---
    if a == A_MFA:
        if r <= LOW_TH: return MFA_LOW_REWARD
        if r <= MID_TH: return MFA_MID_REWARD
        return MFA_HIGH_REWARD

    # --- Reject ---
    if r <= LOW_TH:  return REJECT_LOW_PENALTY
    if r <= MID_TH:  return REJECT_MID_PENALTY
    return REJECT_HIGH_REWARD

# ───── 5. Q-table 初始化 ─────────────────────────
Q = np.zeros((len(all_states), 3))

# ───── 6. Offline warm-up (若有檔案) ────────────
CSV_FILE = Path("fido2_q_learning_simulated2.csv")
if CSV_FILE.exists():
    df_sim = pd.read_csv(CSV_FILE).rename(columns={
        "upFlag":"up","uvFlag":"uv","hasUnknownExt":"unk",
        "rpIdMatch":"rp","signCountRisk":"signR",
        "AuthenticatorRisk":"authR"})
    for _ in range(5):
        for _, row in df_sim.iterrows():
            s = (row.accRisk,row.up,row.uv,row.unk,row.rp,row.signR,row.authR)
            a = int(row.action); idx = state2idx[s]
            Q[idx,a] += ALPHA * (reward_fn(s,a) - Q[idx,a])

# ───── 7. transition() ──────────────────────────
def transition(s, a):
    acc,up,uv,unk,rp,sign,auth = s
    return (next_acc_risk(acc,a), up, uv, unk, rp, sign, auth)

# ───── 7b. 驗證集 Accuracy 計算函式 ──────────────
def eval_accuracy(Q_table):
    preds=[]
    for _,row in val_df.iterrows():
        st = tuple(int(row[c]) for c in VAL_COLS)
        preds.append(int(Q_table[state2idx[st]].argmax()))
    return np.mean(preds == val_df["action"])

# ───── 8. Online Q-learning (fixed ε) ───────────
counter = Counter()
acc_history = []          # (episodes , accuracy , elapsed_sec)
t0 = time.time()

for ep in range(EPISODES):
    s = rng.choice(all_states)
    for _ in range(MAX_STEPS):
        idx = state2idx[s]
        act = rng.choice(actions) if rng.random() < EPS_FIXED else int(Q[idx].argmax())
        counter[act] += 1

        r = reward_fn(s,act)
        r_adj = r - LAMBDA * (rng.random() < 0.02)
        s_next = transition(s,act); idx_n = state2idx[s_next]
        Q[idx,act] += ALPHA * (r_adj + GAMMA * Q[idx_n].max() - Q[idx,act])
        s = s_next

    # －－ 每隔 EVAL_EVERY 回合評估一次－－
    if (ep+1) % EVAL_EVERY == 0:
        acc_now = eval_accuracy(Q)
        acc_history.append((ep+1, acc_now, time.time()-t0))
        print(f"[Eval] Episode {ep+1:5d} | Validation Accuracy = {acc_now:.4f}")

# ───── 9. Save & diagnostics ────────────────────
np.save("q_table.npy", Q)

tot = sum(counter.values())
print("\n=== Action distribution ===")
for a, name in enumerate(["ACCEPT","MFA","REJECT"]):
    print(f"{name:7s}: {counter[a]:7d} ({counter[a]/tot:.2%})")

# ───── 10. Episodes vs Accuracy 圖 ───────────────
if acc_history:
    eps_axis, acc_vals, sec_vals = zip(*acc_history)

    fig, ax1 = plt.subplots(figsize=(6.8,4.2))
    ax1.plot(eps_axis, acc_vals, marker="^", lw=2,
             color="tab:blue", label="Accuracy")
    ax1.set_xlabel("Number of Episodes")
    ax1.set_ylabel("Accuracy", color="tab:blue")
    ax1.set_ylim(0, 1.0)
    ax1.tick_params(axis='y', labelcolor="tab:blue")

    # (可選) 累積時間 bar
    ax2 = ax1.twinx()
    ax2.bar(eps_axis, [t/60 for t in sec_vals],
            width=EVAL_EVERY*0.8, alpha=0.25,
            color="tab:green", label="Time (minutes)")
    ax2.set_ylabel("Minutes", color="tab:green")
    ax2.tick_params(axis='y', labelcolor="tab:green")

    h1,l1 = ax1.get_legend_handles_labels()
    h2,l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1+h2, l1+l2, loc="lower right")

    ax1.set_title("Validation Accuracy vs Number of Episodes\n"
                  f"(α={ALPHA}, γ={GAMMA}, ε={EPS_FIXED})")
    plt.tight_layout(); plt.show()
else:
    print("\n⚠ 未產生 Accuracy 歷史，請確認 EVAL_EVERY 參數")
