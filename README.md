# VVRP

VVRP（Virtual Versatile Routing Platform）是一個使用 Python 開發的路由器軟體。命令列介面參考華為 VRP 與 Cisco CLI 的操作習慣，資料平面目前在 Windows 上透過 Npcap 收發封包。

## 架構原則

- VVRP 是進程與核心生命週期的擁有者。
- CMD 是 VVRP 進程內的操作員 Shell 模組，不是系統核心。
- DPlane 隔離作業系統與 Npcap 等平台差異。
- IFNET 以上的模組不攜帶作業系統接口識別資訊。
- RM 負責路由管理與選路，只有活躍路由會下發 FIB。
- FIB 保存實際指導轉發的表項，不反向查詢 RM。
- FWD 只按接口類型分派封包，不解析或構造 Ethernet frame。
- ETHERNET 負責 Ethernet adjacency、ARP 解析、Ethernet frame 收發與封裝。
- SOCK 為協議和應用提供 VVRP 自己的 Socket 介面。

## 環境

- Python 3.11 或更新版本
- Windows 封包收發需要 Npcap
- 涉及原始封包與網卡操作時，通常需要系統管理員權限

安裝相依套件：

```powershell
python -m pip install -e .
```

## 啟動

在專案根目錄執行：

```powershell
python -m VVRP
```

VVRP 會先啟動核心 runtime，再啟動 CMD 模組並顯示使用者模式提示符：

```text
<Router>
```

`CMD` 不提供獨立的執行入口。

## 基本操作

```text
<Router> enable
Router# config
Router(config)# hostname R1
R1(config)# _
R1(hidden)# show interfaces brief
R1(hidden)# show ip interface brief
R1(hidden)# show ip routing-table
R1(hidden)# show fib
R1(hidden)# show arp
```

常用模式：

| 模式 | 進入方式 | 提示符 |
|---|---|---|
| 使用者模式 | VVRP 啟動後進入 | `<Router>` |
| 特權模式 | `enable` | `Router#` |
| 配置模式 | `config` | `Router(config)#` |
| 接口模式 | `interface eth0` | `Router(config-if-eth0)#` |
| Host 接口模式 | `host interface eth0` | `Router(host-if-eth0)#` |
| 隱藏模式 | `_` | `Router(hidden)#` |

`quit` 返回上一層模式，`exit` 離開 CMD。`save` 保存全局配置，`reload` 重新載入配置，`reboot` 重新啟動 VVRP 進程。

## 命令列特性

- Literal token 大小寫不敏感。
- 支援唯一前綴縮寫與自動補全。
- 即時著色：有效為綠色、存在歧義為黃色、非法為紅色。
- 在命令任意位置輸入 `?` 並按 Enter，可顯示下一個 token 或參數。
- 接口名稱輸入大小寫不敏感，但輸出保留正式名稱，例如 `InLoopBack0` 與 `NULL0`。
- `show` 取代華為 VRP 的 `display`，`no` 取代 `undo`。

## 接口導入與配置

`host interface` 命令族屬於 DPlane 的宿主機調試與適配介面。導入成功後，DPlane 安裝 Ethernet device，ETHERNET 再向 IFNET 提供 VVRP 接口。

```text
Router(hidden)# host interface eth0
Router(host-if-eth0)# import
Router(host-if-eth0)# commit
Router(host-if-eth0)# quit
Router(hidden)# interface eth0
Router(config-if-eth0)# ip address 192.0.2.1 24
Router(config-if-eth0)# save
```

不要在不確定影響範圍時對正在使用的宿主機網卡執行 `shutdown`、`no import` 或修改宿主機 IP 等操作。

## 測試

執行完整測試：

```powershell
python -m unittest discover -s tests
```

啟動核心煙霧測試：

```powershell
python -m VVRP --no-cmd
```

## 開發記錄

每次開發事件由 `tools/codex_logger.py` 記錄，並可使用下列命令重播與生成時間線：

```powershell
python tools/replay.py
python tools/timeline.py
```
