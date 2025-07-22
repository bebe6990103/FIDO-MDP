"""
offline_q_update_mdp.py
--------------------------------------------------
離線多步期望版更新：
   1. 讀 FidoAuthLog (SQLite) 中 done = 0 且 misjudge 非 NULL 的紀錄
   2. 用 Bellman:  Q ← Q + α[(r-λe) + γ·E[maxQ(s')] − Q]
   3. 將這些紀錄的 done 置 1
注意：action 欄位為文字 "ACCEPT" / "MFA" / "REJECT"
"""

import sqlite3, numpy as np
from pathlib import Path

# ────────── 路徑設定 ─────────────────────────
DB_PATH = r"C:\source code\fido2-net-lib-master\fido2-net-lib-master\Demo\fidoLog.db"
Q_PATH  = r"C:\source code\Qlearning_test\q_table.npy"

# ────────── 超參數 ──────────────────────────
ALPHA  = 0.2
LAMBDA = 24
GAMMA  = 0.9            # 多步

# ────────── 狀態索引映射 ───────────────────
acc_vals = [0,1,2]      # accRisk
binary   = [0,1]
tri      = [0,1,2]

all_states = [(a,u,v,k,s)
              for a in acc_vals
              for u in binary
              for v in binary
              for k in binary
              for s in tri]
state2idx = {s:i for i,s in enumerate(all_states)}

# ────────── 動作文字 ↔  整數索引 ────────────
ACTION_MAP = {"ACCEPT":0, "MFA":1, "REJECT":2}

# ────────── 轉移機率矩陣 (3×3×3) ────────────
P_accept = np.array([[0.70,0.20,0.10],
                     [0.30,0.50,0.20],
                     [0.20,0.30,0.50]])
P_mfa    = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.20,0.30,0.50]])
P_reject = np.array([[0.50,0.30,0.20],
                     [0.20,0.50,0.30],
                     [0.10,0.20,0.70]])
P_dict   = {0:P_accept, 1:P_mfa, 2:P_reject}

# ────────── Reward 函式 (與線上相同)──────────
W_ACC,W_UP,W_UV,W_UNK,W_SIGN = 5.0, 0.2, 0.4, 2.5, 3.0
B_ACC,B_MFA,B_REJ = 80,10,22

def risk(state):
    a,u,v,k,s = state
    return W_ACC*a + W_UP*(1-u) + W_UV*(1-v) + W_UNK*k + W_SIGN*s

def reward(state, act):
    r = risk(state)
    if act==0:  # ACCEPT
        return B_ACC if r<=4 else 28-3*r if r<=8 else -18
    if act==1:  # MFA
        return -4   if r<=4 else B_MFA if r<=8 else 8
    # act==2:   # REJECT
    return -45  if r<=4 else -6     if r<=8 else B_REJ

# ────────── 載入 Q-table ────────────────────
Q = np.load(Q_PATH)

# ────────── 連線 SQLite ─────────────────────
con = sqlite3.connect(DB_PATH)
cur = con.cursor()

cur.execute("""
    SELECT id,
           accRisk, upFlag, uvFlag, hasUnknownExt, signCountRisk,
           action, misjudge
    FROM   FidoAuthLog
    WHERE  done = 0 AND misjudge IS NOT NULL
""")
rows = cur.fetchall()
print(f"📥 未處理紀錄：{len(rows)} 筆")

# ────────── 逐筆更新 Q-table ────────────────
for rec in rows:
    rec_id, acc, up, uv, unk, sign, action_txt, mis = rec
    action_txt = (action_txt or "").strip().upper()
    if action_txt not in ACTION_MAP:
        print(f"⚠️  忽略未知 action '{action_txt}' (id={rec_id})")
        continue

    act = ACTION_MAP[action_txt]           # 轉成 0/1/2
    state = (acc, up, uv, unk, sign)
    sidx  = state2idx[state]

    # 1) 即時回饋
    r_t = reward(state, act) - LAMBDA*mis

    # 2) 期望 max Q(s')
    probs = P_dict[act][acc]               # shape (3,)
    exp_max = 0.0
    for acc_p, p in enumerate(probs):
        next_state = (acc_p, up, uv, unk, sign)
        exp_max += p * np.max(Q[state2idx[next_state]])

    td_target = r_t + GAMMA * exp_max
    Q[sidx, act] += ALPHA * (td_target - Q[sidx, act])

    # 標示已處理
    cur.execute("UPDATE FidoAuthLog SET done = 1 WHERE id = ?", (rec_id,))

con.commit()
con.close()

# ────────── 存檔 ────────────────────────────
np.save(Q_PATH, Q)
print("✅ Q-table 已更新並寫回:", Q_PATH)
