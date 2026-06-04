# Batch 8: 文件传输协议修复计划 (FTP/TFTP/SMB/SMB2)

**Goal:** 修复 ftp.py (3 Minor, 2 Style) + tftp.py (1 Critical, 2 Minor, 1 Style) + smb.py (2 Critical, 2 Minor, 1 Style) + smb2.py (4 Minor, 3 Style)

---

## Part A: tftp.py

### Task 1: 修复选项常量类型 (Critical)

- [ ] **Step 1: 修改 line 20-24**

```python
# 修改前:
TFTP_OPT_BLKSIZE = 'blksize'
TFTP_OPT_TSIZE = 'tsize'
TFTP_OPT_TIMEOUT = 'timeout'
TFTP_OPT_TFTP_TYPE = 'tftp_type'
TFTP_OPT_MULTICAST = 'multicast'

# 修改后:
TFTP_OPT_BLKSIZE = b'blksize'
TFTP_OPT_TSIZE = b'tsize'
TFTP_OPT_TIMEOUT = b'timeout'
TFTP_OPT_TFTP_TYPE = b'tftp_type'
TFTP_OPT_MULTICAST = b'multicast'
```

- [ ] **Step 2: 提交** `git commit -m "fix: TFTP option constants must be bytes, not str"`

---

## Part B: smb.py

### Task 2: 修复 SMB_CMD_OPEN 常量 (Critical)

- [ ] **Step 1: 修改 line 53**

```python
# 修改前:
SMB_CMD_OPEN = 0xC0

# 修改后 (MS-CIFS: SMB_COM_OPEN = 0x02):
SMB_CMD_OPEN = 0x02
```

- [ ] **Step 2: 提交** `git commit -m "fix: correct SMB_CMD_OPEN from 0xC0 to 0x02"`

### Task 3: 修复 WriteAndX 阈值 (Critical)

- [ ] **Step 1: 修改 line 289**

```python
# 修改前:
if len(self._params) >= 28:

# 修改后 (WC=12 → 24 bytes):
if len(self._params) >= 24:
```

- [ ] **Step 2: 提交** `git commit -m "fix: SMB1 WriteAndX threshold from 28 to 24 (WC=12)"`

### Task 4: 修复 SMB_FLAGS2 常量名 (Minor)

- [ ] **Step 1: 修改 line 27**

```python
# 修改前:
SMB_FLAGS2_REVERSE_PATH = 0x0400

# 修改后:
SMB_FLAGS2_REPARSE_PATH = 0x0400
```

- [ ] **Step 2: 提交** `git commit -m "fix: rename SMB_FLAGS2_REVERSE_PATH to REPARSE_PATH"`

---

## Part C: smb2.py

### Task 5: 修复 SMB2QueryDirectory 越界读取 (Minor)

- [ ] **Step 1: 修改 line 494-495**

```python
# 修改前:
fn_start = self.file_name_offset - 64 if self.file_name_offset >= 64 else 0

# 修改后:
if self.file_name_offset >= 64 and self.file_name_length:
    fn_start = self.file_name_offset - 64
    self.file_name = buf[fn_start:fn_start + self.file_name_length]
else:
    self.file_name = b''
```

- [ ] **Step 2: 提交** `git commit -m "fix: SMB2 QueryDirectory guard against zero file_name_offset"`

### Task 6: 定义 SMB2_HDR_SIZE 常量 (Style)

- [ ] **Step 1: 在文件顶部添加**

```python
SMB2_HDR_SIZE = 64
```

- [ ] **Step 2: 替换所有硬编码的 `64`**

- [ ] **Step 3: 提交** `git commit -m "style: replace hardcoded 64 with SMB2_HDR_SIZE constant"`
