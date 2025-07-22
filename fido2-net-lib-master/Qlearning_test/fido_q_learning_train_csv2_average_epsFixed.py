# fido_q_learning_train_offline.py  (fixed ε, show hyper-params, 2025-06-23)
import numpy as np, random, itertools, pandas as pd
from collections import Counter
from pathlib import Path
import matplotlib.pyplot as plt

# ───── 0. Hyper-params ─────────────────────────
ALPHA   = 0.3
GAMMA   = 0.9
LAMBDA  = 3
EPISODES, MAX_STEPS = 10_000, 40
EPSILON = 0.3       # 固定探索率 ε

rng = random.Random(42)

# ───── 1. State space ──────────────────────────
acc_vals = [0,1,2]; binary = [0,1]; tri = [0,1,2]
all_states = list(itertools.product(acc_vals, binary, binary,
                                    binary, binary, tri, tri))
state2idx = {s:i for i,s in enumerate(all_states)}

# ───── 2. Actions ──────────────────────────────
A_ACCEPT, A_MFA, A_REJECT = 0,1,2
actions = [A_ACCEPT, A_MFA, A_REJECT]

# ───── 3. accRisk transition ───────────────────
P_accept = np.array([[0.70,0.20,0.10],
                     [0.30,0.50,0.20],
                     [0.20,0.30,0.50]])
P_mfa    = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.20,0.30,0.50]])
P_reject = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.10,0.20,0.70]])
P_dict = {A_ACCEPT:P_accept, A_MFA:P_mfa, A_REJECT:P_reject}
def next_acc_risk(cur:int, act:int)->int:
    return rng.choices([0,1,2], P_dict[act][cur])[0]

# ───── 4. Risk → Reward  (re-shaping for MFA) ────────────
# 權重略調：把「成功驗證 (up/uv)」的重要度拉低，讓 r 更依賴 accRisk/auth
W_ACC, W_UP, W_UV, W_UNK, W_RP, W_SIGN, W_AUTH = 4.0, 0.3, 0.3, 2.0, 2.0, 2.5, 3.0

# ---------- Risk → Reward (Balanced MFA) ----------
LOW_TH, MID_TH = 5, 9

BONUS_ACCEPT_LOW   = 35
MFA_LOW_REWARD     = -10
REJECT_LOW_PENALTY = -40

ACCEPT_MID_PENALTY = -12
MFA_MID_REWARD     = 55      # 超高獎勵
REJECT_MID_REWARD  =  0

PENALTY_ACCEPT_HIGH= -45
MFA_HIGH_REWARD    = 12
REJECT_HIGH_REWARD = 40

def risk_score(s):
    acc, up, uv, unk, rp, sign, auth = s
    return (W_ACC*acc + W_UP*(1-up) + W_UV*(1-uv) +
            W_UNK*unk + W_RP*(1-rp) + W_SIGN*sign + W_AUTH*auth)

def reward_fn(s, a):
    r = risk_score(s)

    # --- Accept ---
    if a == A_ACCEPT:
        if r <= LOW_TH:  return BONUS_ACCEPT_LOW
        if r <= MID_TH:  return ACCEPT_MID_PENALTY
        return PENALTY_ACCEPT_HIGH

    # --- MFA ---
    if a == A_MFA:
        if r <= LOW_TH:  return MFA_LOW_REWARD
        if r <= MID_TH:  return MFA_MID_REWARD
        return MFA_HIGH_REWARD

    # --- Reject ---
    if r <= LOW_TH:   return REJECT_LOW_PENALTY
    if r <= MID_TH:   return REJECT_MID_REWARD
    return REJECT_HIGH_REWARD

# ───── 5. Q-table 初始化 ───────────────────────
Q = np.zeros((len(all_states), 3))

# ───── 6. Offline warm-up (optional) ───────────
CSV_FILE = Path("fido2_q_learning_simulated2.csv")
if CSV_FILE.exists():
    df = pd.read_csv(CSV_FILE).rename(columns={
        "upFlag":"up","uvFlag":"uv","hasUnknownExt":"unk",
        "rpIdMatch":"rp","signCountRisk":"signR",
        "AuthenticatorRisk":"authR"})
    for _ in range(5):                # EPOCHS_OFFLINE = 5
        for _, row in df.iterrows():
            s = (row.accRisk,row.up,row.uv,row.unk,row.rp,row.signR,row.authR)
            a = int(row.action)
            Q[state2idx[s], a] += ALPHA*(reward_fn(s,a) - Q[state2idx[s], a])

# ───── 7. transition() ─────────────────────────
def transition(s,a):
    acc, up, uv, unk, rp, sign, auth = s
    return (next_acc_risk(acc,a), up, uv, unk, rp, sign, auth)

# ───── 8. Online Q-learning ────────────────────
counter, avg_rewards = Counter(), []
for ep in range(EPISODES):
    s = rng.choice(all_states); ep_reward = 0
    for _ in range(MAX_STEPS):
        idx  = state2idx[s]
        act  = rng.choice(actions) if rng.random() < EPSILON else int(Q[idx].argmax())
        counter[act] += 1
        r = reward_fn(s, act); ep_reward += r
        r_adj = r - LAMBDA * (rng.random() < 0.02)
        s_next = transition(s, act); idx_n = state2idx[s_next]
        Q[idx, act] += ALPHA * (r_adj + GAMMA * Q[idx_n].max() - Q[idx, act])
        s = s_next
    avg_rewards.append(ep_reward / MAX_STEPS)

# ───── 9. 儲存 & summary ───────────────────────
np.save("q_table.npy", Q)
print("\n=== Action distribution ===")
tot = sum(counter.values())
for a,name in enumerate(["ACCEPT","MFA","REJECT"]):
    print(f"{name:7s}: {counter[a]:7d} ({counter[a]/tot:.2%})")

# ───── 10. 繪圖，並在圖上顯示超參數 ────────────
win = max(1, EPISODES // 100)
smooth = pd.Series(avg_rewards).rolling(win).mean()

plt.plot(smooth, label="Avg reward (rolling mean)")
plt.title("Average reward per step")
plt.xlabel("Episode"); plt.ylabel("Avg reward"); plt.grid(True)

plt.ylim(22, 40)  # ✅ 固定 Y 軸範圍
#plt.ylim(22, 33)  # ✅ 固定 Y 軸範圍

# 在左上角顯示所有重要超參數，包括 λ
txt = (f"α={ALPHA},  γ={GAMMA},  ε={EPSILON},  λ={LAMBDA}\n"
       f"Episodes={EPISODES},  Max_steps={MAX_STEPS}")
plt.figtext(0.02, 0.98, txt, ha="left", va="top",
            fontsize=8, bbox=dict(facecolor="white", alpha=0.7))

plt.legend(loc="lower right"); plt.show()
