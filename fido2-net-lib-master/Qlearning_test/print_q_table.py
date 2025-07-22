#!/usr/bin/env python
"""
show_qtable.py  ‒‒ 印出 7 維 (432×3) Q-table
─────────────────────────────────────────────
# 全表
python show_qtable.py

# 指定狀態 (7 位字串或 7 個數字)
python show_qtable.py 0101000         # acc=0,up=1,uv=0,unk=1,rp=0,sign=0,auth=0
python show_qtable.py 2 1 1 0 1 0 2

# 指定行號 (0‥431)
python show_qtable.py --idx 123
"""
import sys, argparse, itertools, numpy as np
from pathlib import Path

# ────────── 1. 狀態空間 ──────────
acc_vals  = [0,1,2]
binary    = [0,1]
tri       = [0,1,2]

# 7 維：acc, up, uv, unk, rp, sign, auth
all_states = [(a,u,v,k,r,s,h)
              for a in acc_vals
              for u in binary
              for v in binary
              for k in binary
              for r in binary
              for s in tri
              for h in tri]
state2idx  = {s:i for i,s in enumerate(all_states)}

# ────────── 2. 讀 Q-table ─────────
Q_PATH = Path("q_table.npy")
if not Q_PATH.exists():
    sys.exit("❌ 找不到 q_table.npy")
Q = np.load(Q_PATH)
if Q.shape[0] != len(all_states):
    sys.exit(f"❌ Q-table 行數 ({Q.shape[0]}) 與 432 不符，請確認維度一致")
np.set_printoptions(precision=2, suppress=True)

# ────────── 3. CLI 解析 ──────────
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--idx", type=int, help="row index 0‥431")
args, rest = parser.parse_known_args()

def print_header():
    print("Idx | acc up uv unk rp sign auth |   Accept   MFA   Reject")
    print("----------------------------------------------------------")

def print_row(idx, st):
    a,u,v,k,r,s,h = st
    q0,q1,q2 = Q[idx]
    print(f"{idx:3d} |  {a}   {u}  {v}  {k}   {r}   {s}    {h}   |"
          f"  {q0:7.2f} {q1:6.2f} {q2:8.2f}")

# ────────── 4. 依參數顯示 ─────────
# 4-1 以 --idx 查詢
if args.idx is not None:
    if 0 <= args.idx < len(all_states):
        st = all_states[args.idx]
        print("=== 指定 idx Q 值 ===")
        print_header(); print_row(args.idx, st)
    else:
        sys.exit("❌ idx 必須介於 0‥431")
    sys.exit()

# 4-2 無其它參數 → 印整表
if not rest:
    print("=== Q-Table (432 × 3) ===")
    print_header()
    for i, st in enumerate(all_states):
        print_row(i, st)
    sys.exit()

# 4-3 指定 7 位狀態
if len(rest) == 1 and len(rest[0]) == 7 and rest[0].isdigit():
    digits = list(map(int, rest[0]))
elif len(rest) == 7 and all(r.isdigit() for r in rest):
    digits = list(map(int, rest))
else:
    sys.exit("❌ 請提供 7 位字串 (如 0101000) 或 7 個整數，或 --idx N")

state = tuple(digits)
if state not in state2idx:
    sys.exit("❌ 數值超出範圍 (acc 0-2, up/uv/unk/rp 0-1, sign/auth 0-2)")

idx = state2idx[state]
print("=== 指定狀態 Q 值 ===")
print_header(); print_row(idx, state)
