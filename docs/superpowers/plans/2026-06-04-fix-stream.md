# Batch 1: TCP 流重组修复计划 (stream.py)

**Goal:** 修复 stream.py 中 2 个 Critical、4 个 Minor、1 个 Style 问题

**Files:** `dpkt/stream.py`

---

### Task 1: 修复连接键方向性问题 (Critical)

**Problem:** `StreamReassembler.feed()` 创建的 `conn_id` 是方向性的，导致同一 TCP 连接被拆成两个 Connection。

- [ ] **Step 1: 修改 StreamReassembler.feed() 中的 conn_id 生成逻辑**

```python
# stream.py line 216-224, 修改前:
def feed(self, ip, tcp_pkt):
    """Feed one parsed IP+TCP packet."""
    conn_id = (socket.inet_ntoa(ip.src), tcp_pkt.sport,
               socket.inet_ntoa(ip.dst), tcp_pkt.dport)
    if conn_id not in self.connections:
        if len(self.connections) >= self.max_connections:
            self._evict_one()
        self.connections[conn_id] = Connection(
            src_ip=conn_id[0], src_port=conn_id[1],
            dst_ip=conn_id[2], dst_port=conn_id[3])

# 修改后:
def feed(self, ip, tcp_pkt):
    """Feed one parsed IP+TCP packet."""
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    a = (src_ip, tcp_pkt.sport)
    b = (dst_ip, tcp_pkt.dport)
    if a <= b:
        conn_id = a + b
    else:
        conn_id = b + a
    if conn_id not in self.connections:
        if len(self.connections) >= self.max_connections:
            self._evict_one()
        # Always store as (smaller, larger) for consistent keying
        self.connections[conn_id] = Connection(
            src_ip=conn_id[0], src_port=conn_id[1],
            dst_ip=conn_id[2], dst_port=conn_id[3])
    conn = self.connections[conn_id]
    # Determine direction based on actual packet source
    if src_ip == conn.src_ip and tcp_pkt.sport == conn.src_port:
        conn.c2s.feed(tcp_pkt.seq, tcp_pkt.ack, tcp_pkt.data, tcp_pkt.flags)
    else:
        conn.s2c.feed(tcp_pkt.seq, tcp_pkt.ack, tcp_pkt.data, tcp_pkt.flags)
    # ... rest of method unchanged
```

- [ ] **Step 2: 修改 Connection.feed() 以支持方向判断**

```python
# stream.py line 146-151, 修改前:
def feed(self, ip, tcp):
    """Feed a parsed IP+TCP packet to the correct direction."""
    if tcp.sport == self.src_port:
        self.c2s.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)
    else:
        self.s2c.feed(tcp.seq, tcp.ack, tcp.data, tcp.flags)

# 修改后: 不再需要，方向判断已在 StreamReassembler.feed() 中完成
# 但保留此方法供直接使用 Connection 的场景
def feed(self, src_ip, sport, seq, ack, data, flags):
    """Feed packet data to the correct direction."""
    if src_ip == self.src_ip and sport == self.src_port:
        self.c2s.feed(seq, ack, data, flags)
    else:
        self.s2c.feed(seq, ack, data, flags)
```

- [ ] **Step 3: 更新测试以验证双向连接合并**

```python
def test_stream_reassembler_bidirectional():
    """Both directions of same connection map to same Connection."""
    reasm = StreamReassembler()
    # SYN from client
    ip1 = ip_mod.IP(src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02', p=6)
    tcp1 = tcp_mod.TCP(sport=12345, dport=80, seq=0, flags=tcp_mod.TH_SYN, data=b'')
    reasm.feed(ip1, tcp1)
    # SYN-ACK from server (reversed direction)
    ip2 = ip_mod.IP(src=b'\x0a\x00\x00\x02', dst=b'\x0a\x00\x00\x01', p=6)
    tcp2 = tcp_mod.TCP(sport=80, dport=12345, seq=5000, flags=tcp_mod.TH_SYN | tcp_mod.TH_ACK, data=b'')
    reasm.feed(ip2, tcp2)
    assert len(reasm.connections) == 1  # NOT 2
    conn = list(reasm.connections.values())[0]
    assert conn.c2s.syn_received
    assert conn.s2c.syn_received
```

- [ ] **Step 4: 运行测试验证**

```bash
cd f:\code\python\dpkt_ng
python -m pytest dpkt/stream.py -v
```

- [ ] **Step 5: 提交**

```bash
git add dpkt/stream.py
git commit -m "fix: normalize TCP connection key to merge both directions"
```

---

### Task 2: 修复乱序段合并丢弃尾部数据 (Critical)

**Problem:** 当两个段重叠时，合并逻辑丢弃前一段的尾部。

- [ ] **Step 1: 修复 DirectionBuffer.feed() 中的合并逻辑 (line 80-94)**

```python
# 修改前 (line 86-87):
if overlap_off < len(prev_data):
    new_data = prev_data[:overlap_off] + seg[2]

# 修改后:
if overlap_off < len(prev_data):
    # Overlay new segment onto previous, preserving tail
    new_len = max(len(prev_data), overlap_off + len(seg[2]))
    new_data = bytearray(new_len)
    new_data[:len(prev_data)] = prev_data
    new_data[overlap_off:overlap_off + len(seg[2])] = seg[2]
    new_data = bytes(new_data)
```

- [ ] **Step 2: 添加测试验证尾部保留**

```python
def test_direction_buffer_overlap_preserves_tail():
    """Overlapping merge preserves non-overlapping tail of previous segment."""
    buf = DirectionBuffer()
    buf.feed(seq=0, ack=0, payload=b'', flags=tcp_mod.TH_SYN)
    # First segment: ABCDEFGH at seq=1
    buf.feed(seq=1, ack=0, payload=b'ABCDEFGH', flags=tcp_mod.TH_ACK)
    buf.get_data()  # flush contiguous
    # Out-of-order overlapping segment: XY at seq=5 (overlaps E-F)
    buf.feed(seq=5, ack=0, payload=b'XY', flags=tcp_mod.TH_ACK)
    # The merged segment should be: ABCDXYGH (not ABCDXY)
    assert len(buf.segments) == 1
    assert buf.segments[0][2] == b'ABCDXYGH'
```

- [ ] **Step 3: 运行测试并提交**

```bash
python -m pytest dpkt/stream.py::test_direction_buffer_overlap_preserves_tail -v
git add dpkt/stream.py
git commit -m "fix: preserve tail data when merging overlapping TCP segments"
```

---

### Task 3: 修复 total_buffered 计数 (Minor)

**Problem:** 级联合并未减少 `total_buffered`，导致提前驱逐。

- [ ] **Step 1: 在级联合并后更新 total_buffered (line 69-74)**

```python
# 在 while 循环后添加:
# Update total_buffered after cascade merge
self.total_buffered = len(self.contiguous) + sum(len(d) for _, _, d in self.segments)
```

- [ ] **Step 2: 在乱序合并后也更新 (line 80-94)**

```python
# 在 self.segments = merged 后添加:
self.total_buffered = len(self.contiguous) + sum(len(d) for _, _, d in self.segments)
```

- [ ] **Step 3: 提交**

```bash
git add dpkt/stream.py
git commit -m "fix: correctly track total_buffered after segment merges"
```

---

### Task 4: 移除模块级未使用 import (Style)

- [ ] **Step 1: 移除 line 7 的 `import struct`**（仅在测试函数中使用，应为局部导入）

- [ ] **Step 2: 提交**

```bash
git add dpkt/stream.py
git commit -m "style: move unused struct import to test function"
```
