# dpkt_ng 协议实现修复计划 - 总览

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复审查发现的 101 个协议实现问题（27 Critical, 2 Major, 55 Minor, 17 Style）

**Architecture:** 按依赖关系分 8 个批次修复，每批次可独立执行。stream.py 是基础依赖（影响 filecarver/topology），优先修复。

**Tech Stack:** Python 3, dpkt, struct, socket

---

## 修复顺序与依赖关系

```
Batch 1: stream.py (基础) ──→ Batch 2: filecarver.py/topology.py
Batch 3: quic.py/http3.py/qpack.py (独立)
Batch 4: ieee80211_ie.py + ieee80211.py (独立)
Batch 5: ospf.py/eigrp.py/isis.py (独立)
Batch 6: l2tp.py/vxlan.py/gtp.py (独立)
Batch 7: smtp.py/pop3.py/imap.py (独立)
Batch 8: ftp.py/tftp.py/smb.py/smb2.py (独立)
```

## 问题统计

| 批次 | 文件 | Critical | Major | Minor | Style | 合计 |
|------|------|----------|-------|-------|-------|------|
| 1 | stream.py | 2 | 0 | 4 | 1 | 7 |
| 2 | filecarver.py, topology.py | 4 | 0 | 7 | 1 | 12 |
| 3 | quic.py, http3.py, qpack.py | 8 | 0 | 8 | 0 | 16 |
| 4 | ieee80211_ie.py, ieee80211.py | 7 | 2 | 8 | 1 | 18 |
| 5 | ospf.py, eigrp.py, isis.py | 3 | 0 | 8 | 3 | 14 |
| 6 | l2tp.py, vxlan.py, gtp.py | 2 | 0 | 5 | 3 | 10 |
| 7 | smtp.py, pop3.py, imap.py | 3 | 0 | 7 | 4 | 14 |
| 8 | ftp.py, tftp.py, smb.py, smb2.py, nbss.py | 3 | 0 | 9 | 5 | 17 |
| **总计** | **21 文件** | **32** | **2** | **56** | **18** | **108** |

## 子计划列表

| 批次 | 文件 | 计划文档 |
|------|------|----------|
| 1 | stream.py | [2026-06-04-fix-stream.md](2026-06-04-fix-stream.md) |
| 2 | filecarver.py, topology.py | [2026-06-04-fix-filecarver-topology.md](2026-06-04-fix-filecarver-topology.md) |
| 3 | quic.py, http3.py, qpack.py | [2026-06-04-fix-quic-http3-qpack.md](2026-06-04-fix-quic-http3-qpack.md) |
| 4 | ieee80211_ie.py, ieee80211.py | [2026-06-04-fix-ieee80211.md](2026-06-04-fix-ieee80211.md) |
| 5 | ospf.py, eigrp.py, isis.py | [2026-06-04-fix-routing.md](2026-06-04-fix-routing.md) |
| 6 | l2tp.py, vxlan.py, gtp.py | [2026-06-04-fix-tunnel.md](2026-06-04-fix-tunnel.md) |
| 7 | smtp.py, pop3.py, imap.py | [2026-06-04-fix-email.md](2026-06-04-fix-email.md) |
| 8 | ftp.py, tftp.py, smb.py, smb2.py | [2026-06-04-fix-filetransfer.md](2026-06-04-fix-filetransfer.md) |

## 执行方式

每个子计划包含具体的代码修改步骤。推荐使用 subagent-driven-development 逐批次执行：
1. 每个批次启动一个子代理
2. 子代理按步骤修改代码并运行测试
3. 完成后提交 git commit
4. 继续下一批次
