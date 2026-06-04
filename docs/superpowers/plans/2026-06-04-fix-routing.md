# Batch 5: OSPF/EIGRP/IS-IS 修复计划

**Goal:** 修复 ospf.py (2 Critical, 4 Minor) + eigrp.py (1 Critical, 4 Minor, 1 Style) + isis.py (1 Critical, 4 Minor, 1 Style)

---

## Part A: ospf.py

### Task 1: 修复 AS-External LSA __bytes__ 遗漏 prefix (Critical)

- [ ] **Step 1: 修改 LSAASExternal.__bytes__ (line 704-708)**

```python
# 在 metric 和 forwarding 之间插入 prefix:
body = struct.pack('>I', self.mask) + bytes([self.flags]) + struct.pack('>I', self.metric)[1:]
body += self.prefix  # NEW: include variable-length prefix
body += struct.pack('>I', self.forwarding) + struct.pack('>I', self.tag)
```

- [ ] **Step 2: 修复 __len__ (line 711-712)**

```python
# 修改前:
return self.__hdr_len__ + 16

# 修改后:
return self.__hdr_len__ + 16 + len(self.prefix)
```

- [ ] **Step 3: 提交** `git commit -m "fix: include prefix in OSPF AS-External LSA serialization"`

### Task 2: 修复 LSARouterV3 丢失 Options (Minor)

- [ ] **Step 1: 修改 line 271**

```python
# 修改前:
body = bytes([self.flags, 0, 0, 0])

# 修改后:
body = bytes([self.flags]) + bytes(self.opts)
```

- [ ] **Step 2: 提交** `git commit -m "fix: preserve Options field in OSPFv3 Router LSA serialization"`

---

## Part B: eigrp.py

### Task 3: 修复 ExternalRouteTLV 序列化不匹配 (Critical)

- [ ] **Step 1: 修改 __bytes__ (line 176-183)**

```python
# 修改前: struct.pack('>IIIBB2s', ...) 多了 2 字节保留
# 修改后: 与 unpack 对齐，14 字节
body = struct.pack('>IIIBB', self.origin_router, self.origin_as, self.tag,
                   self.ext_proto, self.ext_flags)
```

- [ ] **Step 2: 提交** `git commit -m "fix: align EIGRP ExternalRouteTLV serialization with unpack"`

### Task 4: 修复 AFI_IPV6 常量 (Minor)

- [ ] **Step 1: 修改 line 36-37**

```python
# 修改前:
AFI_IPV6 = 16384

# 修改后:
AFI_IPV6 = 2  # Standard AFI for IPv6
```

- [ ] **Step 2: 提交** `git commit -m "fix: correct EIGRP AFI_IPV6 constant to 2"`

---

## Part C: isis.py

### Task 5: 修复 LSP flags 字段丢失 (Critical)

- [ ] **Step 1: 在 ISISLSPL1.unpack 中保存 flags (line 111)**

```python
# 在 TLV 解析前添加:
self.flags = buf[18]  # P/ATT/overload/IS Type bits
```

- [ ] **Step 2: 提交** `git commit -m "fix: preserve IS-IS LSP flags byte (P/ATT/overload)"`

### Task 6: 修复 IP Internal Reach TLV 条目格式 (Minor)

- [ ] **Step 1: 修改 ISISIPIntReachTLV.unpack (line 167-174)**

```python
# 修改前: 13 字节条目 (metric(4)+ctrl(1)+prefix(4)+mask(4))
# 修改后: 12 字节条目 (RFC 1195 §3.2.2)
while off + 12 <= len(self.value):
    default_metric = self.value[off]
    delay_metric = self.value[off+1]
    expense_metric = self.value[off+2]
    error_metric = self.value[off+3]
    prefix = self.value[off+4:off+8]
    mask = self.value[off+8:off+12]
    self.entries.append({
        'metric': default_metric,
        'prefix': prefix,
        'mask': mask,
    })
    off += 12
```

- [ ] **Step 2: 提交** `git commit -m "fix: correct IS-IS IP Reach TLV entry size to 12 bytes"`
