# Python 路由器風格 CLI 解釋器

這是一個小型 Cisco/華為風格命令行解釋器示例，重點功能：

- 命令縮寫：`sho` 可唯一補全為 `show`。
- 即時著色：唯一有效為綠色，歧義為黃色，非法為紅色。
- 正則參數：例如 `show host interfaces <name:[A-Za-z0-9_.:/%-]+>`。
- 歷史命令：上下鍵回填歷史，必須再次回車才會執行。
- handler 分發：命令解析後調用對應 Python 函數。
- 模式/級別：一般模式、特權模式、配置模式、接口模式、隱藏模式。

## 安裝與運行

```powershell
python -m pip install -e .
python -m VVRP.CCmd
```

如果只想測試核心解析器，不需要安裝 `prompt_toolkit`：

```powershell
python -m unittest discover -s tests
```

## 示例命令

```text
<Router> enable
Router# config
Router(config)# _
(Router-hidden)# host interfaces eth3
(Router-host-if-eth3)# import
(Router-host-if-eth3)# commit
(Router-host-if-eth3)# quit
Router(config)# hostname R1
Router(config)# show hostname
ping 192.168.1.1
ping 2001:db8::1
ping example.com
show
show version
show host interfaces
show host interfaces brief
show host interfaces eth3
show dplane interfaces
Router(config)# _
(Router-hidden)# host interfaces eth3
(Router-host-if-eth3)# no import
(Router-host-if-eth3)# commit
help
exit
```

## 上下文幫助

在任何模式、任何命令位置輸入 `?` 並按回車，會顯示當前位置可輸入的下一個命令 token 或參數：

```text
<Router> show ?
  interfaces  Show system interfaces
  version    Show software version

<Router> show host interfaces ?
  brief  Show brief system interface summary
  <name>  Show system interface detail

<Router> show host interfaces brief ?
  <cr>  Show brief system interface summary
```

`show host interfaces brief` uses a Huawei VRP-style interface summary format:
`Interface PHY Protocol InUti OutUti inErrors outErrors`.
`show host interfaces` displays detailed interface information, including the VVRP IFNET Index in `0x` hexadecimal format.
`shutdown` and `no shutdown` are interface-mode IFNET commands that apply the change to the OS network adapter. They usually require Administrator/root privileges. Loopback interfaces cannot be shut down.
Do not use `eth0` for destructive interface tests; use `eth3` in this workspace.

幫助文字來自命令註冊時的 `help_text`。如果下一個 token 是參數，例如 `<name:...>`，幫助也會自動沿用該完整命令的 `help_text`。

`show` 是 show 家族命令的父命令，會按當前模式列出該模式可用的 `show ...` 子命令。

## 模式和提示符

| 模式 | 進入命令 | 提示符 |
|---|---|---|
| 一般模式 | 程序啟動時進入 | `<Router>` |
| 特權模式 | `enable` | `Router#` |
| 配置模式 | `config` | `Router(config)#` |
| 主機接口模式 | `host interfaces eth3` | `(Router-host-if-eth3)#` |
| 隱藏模式 | `_` | `(Router-hidden)#` |

`quit` 在特權模式、配置模式、接口模式和隱藏模式下可用，用於回到上一級模式；一般模式是最上層，不提供 `quit`，退出程序請使用 `exit`。

隱藏入口 `_` 可以手動輸入執行，但不會出現在 `?`、`help` 或補全候選裡。

命令不會無條件繼承上一級模式。每條命令都要通過 `modes=(...)` 明確註冊可用模式；如果一條命令只註冊到 `user` 和 `privileged`，那它就只能在這兩個模式使用。

## 擴展命令

```python
from VVRP.CCmd import CommandRegistry, CommandResult

registry = CommandRegistry()

@registry.command(
    "show route <prefix:[0-9./]+>",
    help_text="Show a route entry",
    modes=("user", "privileged"),
)
def show_route(ctx, args):
    return CommandResult(message=f"route = {args['prefix']}")
```
