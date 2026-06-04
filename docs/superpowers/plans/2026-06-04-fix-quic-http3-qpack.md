# Batch 3: QUIC/HTTP3/QPACK 修复计划

**Goal:** 修复 quic.py (6 Critical, 6 Minor)、http3.py (6 Minor)、qpack.py (2 Critical, 5 Minor)

**Files:** `dpkt/quic.py`, `dpkt/http3.py`, `dpkt/qpack.py`

---

## Part A: quic.py

### Task 1: 修复 decode_varint 边界检查 (Minor)

- [ ] **Step 1: 添加越界检查和缓冲区长度验证**

```python
# line 8-16, 修改前:
def decode_varint(buf, offset=0):
    """Decode QUIC variable-length integer. Returns (value, bytes_consumed)."""
    if offset >= len(buf): return 0, 0
    b = buf[offset]
    tag = b >> 6
    if tag == 0: return (b & 0x3f, 1)
    elif tag == 1: return (struct.unpack('>H', buf[offset:offset+2])[0] & 0x3fff, 2)
    elif tag == 2: return (struct.unpack('>I', buf[offset:offset+4])[0] & 0x3fffffff, 4)
    else: return (struct.unpack('>Q', buf[offset:offset+8])[0] & 0x3fffffffffffffff, 8)

# 修改后:
def decode_varint(buf, offset=0):
    """Decode QUIC variable-length integer. Returns (value, bytes_consumed).
    Raises dpkt.NeedData if buffer is too short."""
    if offset >= len(buf):
        raise dpkt.NeedData('varint: buffer too short')
    b = buf[offset]
    tag = b >> 6
    if tag == 0:
        return (b & 0x3f, 1)
    elif tag == 1:
        if offset + 2 > len(buf):
            raise dpkt.NeedData('varint: need 2 bytes')
        return (struct.unpack('>H', buf[offset:offset+2])[0] & 0x3fff, 2)
    elif tag == 2:
        if offset + 4 > len(buf):
            raise dpkt.NeedData('varint: need 4 bytes')
        return (struct.unpack('>I', buf[offset:offset+4])[0] & 0x3fffffff, 4)
    else:
        if offset + 8 > len(buf):
            raise dpkt.NeedData('varint: need 8 bytes')
        return (struct.unpack('>Q', buf[offset:offset+8])[0] & 0x3fffffffffffffff, 8)
```

- [ ] **Step 2: 提交** `git commit -m "fix: add bounds checking to QUIC decode_varint"`

### Task 2: 修复 ACK 帧缺少 first_ack_range (Critical)

- [ ] **Step 1: 添加 first_ack_range 字段**

```python
# line 98-109, 修改 QUICAckFrame.unpack:
class QUICAckFrame(QUICFrame):
    """ACK frame (0x02/0x03)."""
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.largest_ack, n = decode_varint(buf, off); off += n
        self.ack_delay, n = decode_varint(buf, off); off += n
        self.block_count, n = decode_varint(buf, off); off += n
        self.first_ack_range, n = decode_varint(buf, off); off += n  # NEW
        self.blocks = []
        for _ in range(self.block_count):
            gap, n = decode_varint(buf, off); off += n
            ack_len, n = decode_varint(buf, off); off += n
            self.blocks.append((gap, ack_len))
```

- [ ] **Step 2: 更新测试**

```python
def test_quic_ack_frame():
    """ACK frame with first_ack_range."""
    # Build: type(0x02) + largest_ack(10) + ack_delay(0) + block_count(0) + first_ack_range(5)
    buf = bytes([FRAME_ACK]) + encode_varint(10) + encode_varint(0) + encode_varint(0) + encode_varint(5)
    f = QUICAckFrame(buf)
    assert f.largest_ack == 10
    assert f.first_ack_range == 5
    assert f.block_count == 0
```

- [ ] **Step 3: 提交** `git commit -m "fix: add missing first_ack_range to QUIC ACK frame"`

### Task 3: 修复 ConnectionClose 帧 (Critical)

- [ ] **Step 1: 区分 0x1c/0x1d 类型，添加 reason_phrase_length**

```python
# line 122-127, 修改前:
class QUICConnectionCloseFrame(QUICFrame):
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.error_code, n = decode_varint(buf, off); off += n
        self.frame_type, n = decode_varint(buf, off); off += n
        self.reason = buf[off:]

# 修改后:
FRAME_CONNECTION_CLOSE_APP = 0x1d

class QUICConnectionCloseFrame(QUICFrame):
    def unpack(self, buf):
        self.type = buf[0]; off = 1
        self.error_code, n = decode_varint(buf, off); off += n
        if self.type == FRAME_CONNECTION_CLOSE:  # 0x1c: transport close
            self.frame_type, n = decode_varint(buf, off); off += n
        else:  # 0x1d: application close, no frame_type field
            self.frame_type = None
        reason_len, n = decode_varint(buf, off); off += n
        self.reason = buf[off:off + reason_len]
```

- [ ] **Step 2: 注册 0x1d 到帧分发表**

```python
# line 130-135, 添加:
_frame_sw = {
    ...
    FRAME_CONNECTION_CLOSE: QUICConnectionCloseFrame,
    FRAME_CONNECTION_CLOSE_APP: QUICConnectionCloseFrame,  # NEW
    ...
}
```

- [ ] **Step 3: 提交** `git commit -m "fix: distinguish QUIC transport/app connection close frames"`

### Task 4: 修复 parse_frames 偏移推进 (Critical)

- [ ] **Step 1: 计算每帧实际消耗字节数**

```python
# line 142-149, 修改前:
def parse_frames(buf):
    frames = []; off = 0
    while off < len(buf):
        cls = get_frame_parser(buf[off])
        f = cls(buf[off:]); frames.append(f)
        if f.type == FRAME_PADDING: off += 1
        else: off += 1  # BUG: always 1
    return frames

# 修改后:
def parse_frames(buf):
    frames = []; off = 0
    while off < len(buf):
        frame_type = buf[off]
        if frame_type == FRAME_PADDING:
            off += 1
            continue
        cls = get_frame_parser(frame_type)
        try:
            f = cls(buf[off:])
            frames.append(f)
            # Calculate actual frame size
            if hasattr(f, '__len__'):
                off += len(f)
            elif isinstance(f, QUICStreamFrame):
                off += 1 + len(encode_varint(f.stream_id))
                if f.type & 0x04: off += len(encode_varint(f.offset))
                if f.type & 0x02: off += len(encode_varint(f.length))
                off += len(f.data)
            elif isinstance(f, QUICCryptoFrame):
                off += len(f)
            elif isinstance(f, QUICAckFrame):
                off += 1 + len(encode_varint(f.largest_ack)) + len(encode_varint(f.ack_delay))
                off += len(encode_varint(f.block_count)) + len(encode_varint(f.first_ack_range))
                for gap, ack_len in f.blocks:
                    off += len(encode_varint(gap)) + len(encode_varint(ack_len))
            else:
                off += 1  # fallback: skip type byte
        except (dpkt.NeedData, IndexError, struct.error):
            break
    return frames
```

- [ ] **Step 2: 提交** `git commit -m "fix: advance parse_frames by actual frame size, not always 1"`

### Task 5: 修复 Long Header Retry 包和 Initial 特殊处理 (Critical)

- [ ] **Step 1: 移除 Initial 特殊处理，添加 Retry 分支**

```python
# line 186-192, 修改前:
n_bytes = (self.flags & 3) + 1
if self.long_pkt_type == LONG_INITIAL and (self.flags & 3) == 2:
    n_bytes = 4  # BUG: no RFC basis
self.pkt_number = remaining[:n_bytes]

# 修改后:
if self.long_pkt_type == LONG_RETRY:
    # Retry packet: token + integrity tag (16 bytes)
    self.retry_token = remaining[:-16]
    self.retry_integrity_tag = remaining[-16:]
    self.pkt_number = b''
    self.data = b''
    self.frames = []
    return
n_bytes = (self.flags & 3) + 1  # RFC 9000 §17.2
self.pkt_number = remaining[:n_bytes]
```

- [ ] **Step 2: 提交** `git commit -m "fix: handle QUIC Retry packets, remove spurious Initial override"`

### Task 6: 修复 Short Header 硬编码 DCID 长度 (Critical)

- [ ] **Step 1: 添加 dcid_len 参数**

```python
# line 216-222, 修改前:
class QUICShortHeader(dpkt.Packet):
    def unpack(self, buf):
        self.flags = buf[0]
        self.dcid = buf[1:21]  # BUG: hardcoded 20
        self.pkt_number = buf[21:25]

# 修改后:
class QUICShortHeader(dpkt.Packet):
    def unpack(self, buf, dcid_len=0):
        self.flags = buf[0]
        self.dcid = buf[1:1 + dcid_len]
        pn_offset = 1 + dcid_len
        pn_len = (self.flags & 3) + 1  # PN length from lower 2 bits
        self.pkt_number = buf[pn_offset:pn_offset + pn_len]
        payload_offset = pn_offset + pn_len
        self.frames = parse_frames(buf[payload_offset:]) if payload_offset < len(buf) else []
        self.data = b''
```

- [ ] **Step 2: 更新 QUIC.__new__ 传递 dcid_len**

```python
# 需要从连接上下文获取 dcid_len，或文档化限制
```

- [ ] **Step 3: 提交** `git commit -m "fix: parameterize QUIC Short Header DCID and PN length"`

---

## Part B: http3.py

### Task 7: 修复 varint 边界检查 + 消除重复代码 (Minor)

- [ ] **Step 1: 从 quic.py 导入 decode_varint/encode_varint**

```python
# line 1-6, 修改前:
from __future__ import absolute_import, print_function
import struct

# 修改后:
from .quic import decode_varint, encode_varint
```

- [ ] **Step 2: 删除本地 _decode_varint (line 13-18)**

- [ ] **Step 3: 更新 DataFrame.__bytes__ 使用 encode_varint**

- [ ] **Step 4: 提交** `git commit -m "fix: reuse QUIC varint functions in HTTP/3, add bounds checking"`

---

## Part C: qpack.py

### Task 8: 修复编码器/请求流解析偏移 (Critical)

- [ ] **Step 1: 修复 parse_qpack_encoder (line 124-136)**

```python
# 修改前:
def parse_qpack_encoder(buf):
    insts = []; off = 0
    while off < len(buf):
        ...
        insts.append(cls(buf[off:]))
        off += 1  # BUG

# 修改后:
def parse_qpack_encoder(buf):
    insts = []; off = 0
    while off < len(buf):
        prefix = buf[off] & 0xe0
        if prefix == 0x20: cls = QPACKDynamicCapacity
        elif prefix == 0x00: cls = QPACKDuplicate
        elif buf[off] & 0x80: cls = QPACKEncoderInsertRef
        elif buf[off] & 0x40: cls = QPACKEncoderInsertNoRef
        else: break
        inst = cls(buf[off:])
        insts.append(inst)
        # Advance by actual consumed bytes
        if hasattr(inst, '_consumed'):
            off += inst._consumed
        elif hasattr(inst, 'value_len') and hasattr(inst, 'name_index'):
            off += inst._consumed if hasattr(inst, '_consumed') else 1
        else:
            off += 1
    return insts
```

- [ ] **Step 2: 同样修复 parse_qpack_request (line 138-150)**

```python
# 修改后:
def parse_qpack_request(buf):
    insts = []; off = 0
    while off < len(buf):
        b = buf[off]
        if b & 0x80: cls = QPACKIndexedField
        elif b & 0x40: cls = QPACKLiteralNameRef
        elif b & 0x20: cls = QPACKLiteralLiteral
        elif b & 0x10: cls = QPACKPostBase
        else: break
        inst = cls(buf[off:])
        insts.append(inst)
        if hasattr(inst, '_consumed'):
            off += inst._consumed
        else:
            # Calculate from parsed fields
            off += 1  # fallback
    return insts
```

- [ ] **Step 3: 为每个指令类添加 _consumed 属性**

```python
# 在各类的 unpack 方法末尾添加 self._consumed 计算
# 例如 QPACKLiteralNameRef:
def unpack(self, buf):
    self.prefix = 0x40
    self.static = bool(buf[0] & 0x10)
    self.name_index, n = _decode_int(buf, 4)
    self.value_len, m = _decode_int(buf[n:], 7)
    self.value = buf[n+m:n+m+self.value_len]
    self._consumed = n + m + self.value_len  # NEW
```

- [ ] **Step 4: 提交** `git commit -m "fix: advance QPACK parser by actual instruction size, not 1"`
