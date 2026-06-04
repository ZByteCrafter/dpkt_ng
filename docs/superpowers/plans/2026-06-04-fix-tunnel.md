# Batch 6: L2TP/VXLAN/GTP 修复计划

**Goal:** 修复 l2tp.py (2 Critical, 2 Minor, 1 Style) + vxlan.py (3 Minor, 1 Style) + gtp.py (1 Critical, 3 Minor, 1 Style)

---

## Part A: l2tp.py

### Task 1: 修复标志位域布局 (Critical)

- [ ] **Step 1: 修改 __bit_fields__ (line 241-249)**

```python
# 修改前 (缺少 O/P 位，ver 位置错误):
('t', 1), ('l', 1), ('_rsv1', 2), ('s', 1), ('_rsv2', 1), ('ver', 4), ('_rsv3', 6)

# 修改后 (RFC 2661 §3.1):
('t', 1), ('l', 1), ('_rsv1', 2), ('s', 1), ('_rsv2', 1),
('o', 1), ('p', 1), ('_rsv3', 4), ('ver', 4),
```

- [ ] **Step 2: 更新默认 _flags 值的注释**

```python
# line 235: 注释改为
# T(1)+L(1)+rsvd(2)+S(1)+rsvd(1)+O(1)+P(1)+rsvd(4)+Ver(4)
_flags = 0x0002  # T=0, L=0, S=0, Ver=2
```

- [ ] **Step 3: 提交** `git commit -m "fix: correct L2TP flag bit-field layout (add O/P bits, fix ver position)"`

### Task 2: 修复测试中的 P 位 (Minor)

- [ ] **Step 1: 修改 line 372 的测试值**

```python
# 修改前:
0xC882  # P bit set (invalid for control message)

# 修改后:
0xC802  # T=1, L=1, S=1, Ver=2, P=0
```

- [ ] **Step 2: 提交** `git commit -m "fix: L2TP test value - clear P bit for control message"`

---

## Part B: vxlan.py

### Task 3: 添加 VNI 范围验证 (Minor)

- [ ] **Step 1: 修改 line 42**

```python
# 修改前:
struct.pack('>I', self.vni)[1:]

# 修改后:
struct.pack('>I', self.vni & 0xFFFFFF)[1:]
```

- [ ] **Step 2: 提交** `git commit -m "fix: mask VXLAN VNI to 24 bits before serialization"`

---

## Part C: gtp.py

### Task 4: 修复 F-TEID IE 位域偏移 (Critical)

- [ ] **Step 1: 修改 line 98-111**

```python
# 修改前 (全部偏移 1 位):
self.iface = flags & 0x1f    # 5 bits
self.v4 = (flags >> 5) & 1
self.v6 = (flags >> 6) & 1

# 修改后 (3GPP TS 29.274 §8.22):
self.iface = flags & 0x0f    # 4 bits (Interface Type)
self.v4 = (flags >> 4) & 1   # bit 4
self.v6 = (flags >> 5) & 1   # bit 5
```

- [ ] **Step 2: 提交** `git commit -m "fix: correct GTP F-TEID IE bit-field extraction (iface=4bits, v4/v6 positions)"`
