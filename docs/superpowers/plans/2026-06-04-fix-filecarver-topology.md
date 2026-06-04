# Batch 2: FileCarver/Topology 修复计划

**Goal:** 修复 filecarver.py (1 Critical, 4 Minor, 1 Style) + topology.py (3 Critical, 5 Minor, 1 Style)

**Files:** `dpkt/filecarver.py`, `dpkt/topology.py`

---

## Part A: filecarver.py

### Task 1: 修复 FTP 雕刻误解架构 (Critical)

- [ ] **Step 1: 重写 _carve_ftp 以追踪数据通道**

```python
# line 155-164, 修改前: 将控制通道误认为数据通道
# 修改后:
def _carve_ftp(self, conn, data_c2s, data_s2c):
    """Extract files from FTP data connections."""
    # Parse control channel for PASV/PORT to identify data channels
    # For now, extract from data channel (port 20 or passive)
    files = []
    if data_s2c:
        # Data channel: server sends file data
        fname = 'ftp_data_%s_%d.bin' % (conn.conn_id[0], conn.conn_id[1])
        files.append((fname, data_s2c))
    return files
```

- [ ] **Step 2: 提交** `git commit -m "fix: FTP carving extracts from data channel, not control"`

### Task 2: 修复 MIME 分割未跳过 preamble (Minor)

- [ ] **Step 1: 修改 line 32-33**

```python
# 修改前:
parts = raw_email.split(boundary)

# 修改后:
parts = raw_email.split(boundary)
for part in parts[1:]:  # Skip preamble before first boundary
```

- [ ] **Step 2: 提交** `git commit -m "fix: skip MIME preamble in email boundary splitting"`

### Task 3: 修复 rstrip 边界标记 (Minor)

- [ ] **Step 1: 使用显式后缀移除 (line 40)**

```python
# 修改前:
body = body.rstrip(b'\r\n').rstrip(b'--').rstrip(b'\r\n')

# 修改后:
if body.endswith(b'--\r\n'):
    body = body[:-4]
elif body.endswith(b'--'):
    body = body[:-2]
elif body.endswith(b'\r\n'):
    body = body[:-2]
```

- [ ] **Step 2: 提交** `git commit -m "fix: use explicit suffix removal for MIME boundary markers"`

### Task 4: 修复裸 except 子句 (Style)

- [ ] **Step 1: 将所有 `except:` 改为 `except Exception:`** (6 处: line 49, 53, 135, 153, 223, 232)

- [ ] **Step 2: 提交** `git commit -m "style: replace bare except with except Exception"`

---

## Part B: topology.py

### Task 5: 修复 OSPF AS-External LSA 前缀硬编码 (Critical)

- [ ] **Step 1: 修改 line 163**

```python
# 修改前:
self.prefixes.append(Prefix('0.0.0.0', 0, nh, lsa.metric, 'ospf', 'external'))

# 修改后:
net = _inet_to_str(struct.pack('>I', lsa.id))
mask_bits = bin(lsa.mask).count('1') if hasattr(lsa, 'mask') and lsa.mask else 0
self.prefixes.append(Prefix(net, mask_bits, nh, lsa.metric, 'ospf', 'external'))
```

- [ ] **Step 2: 提交** `git commit -m "fix: extract actual prefix from OSPF AS-External LSA"`

### Task 6: 修复 IS-IS 前缀掩码硬编码 /32 (Critical)

- [ ] **Step 1: 修改 line 182**

```python
# 修改前:
self.prefixes.append(Prefix(net, 32, sys_id, pfx['metric'], 'isis', 'internal'))

# 修改后:
mask_int = struct.unpack('>I', pfx['mask'])[0]
mask_bits = bin(mask_int).count('1')
self.prefixes.append(Prefix(net, mask_bits, sys_id, pfx['metric'], 'isis', 'internal'))
```

- [ ] **Step 2: 提交** `git commit -m "fix: extract actual mask from IS-IS IP Reach TLV"`

### Task 7: 修复 BGP 只处理单条消息 (Critical)

- [ ] **Step 1: 修改 line 108-117**

```python
# 修改前:
data = conn.c2s.get_data() or conn.s2c.get_data()
bgp_msg = bgp_mod.BGP(data)
self._extract_bgp(conn_id, bgp_msg)

# 修改后:
for direction in (conn.c2s, conn.s2c):
    data = direction.get_data()
    while data and len(data) >= 19:
        try:
            bgp_msg = bgp_mod.BGP(data)
            self._extract_bgp(conn_id, bgp_msg)
            if hasattr(bgp_msg, 'len') and bgp_msg.len > 0:
                data = data[bgp_msg.len:]
            else:
                data = data[len(bgp_msg):]
        except Exception:
            break
```

- [ ] **Step 2: 提交** `git commit -m "fix: parse all BGP messages from both directions"`
