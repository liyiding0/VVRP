# Python 路由器軟體，界面為Cisco/華為風格�?CLI 解釋�?

這是一個小�?Cisco/華為CLI風格的路由器軟件（含命令行解釋器），命令行有如下特點�?

- 命令縮寫：`sho` 可唯一補全�?`show`�?
- 即時著色：唯一有效為綠色，歧義為黃色，非法為紅色�?
- 正則參數：例�?`show host interface <name:[A-Za-z0-9_.:/%-]+>`�?
- 歷史命令：上下鍵回填歷史，必須再次回車才會執行�?
- handler 分發：命令解析後調用對應 Python 函數�?
- 模式/級別：一般模式、特權模式、配置模式、接口模式、隱藏模式�?

## 安裝與運�?

```powershell
python -m pip install -e .
python -m src.CCmd
```

如果只想測試核心解析器，不需要安�?`prompt_toolkit`�?

```powershell
python -m unittest discover -s tests
```

## 示例命令

```text
<Router> enable
Router# config
Router(config)# _
Router(hidden)# host interface eth3
Router(host-if-eth3)# import
Router(host-if-eth3)# commit
Router(host-if-eth3)# quit
Router(config)# hostname R1
Router(config)# show hostname
ping 192.168.1.1
ping 2001:db8::1
ping example.com
show
show version
show interfaces
show interfaces brief
show interfaces eth3
show dplane interfaces
show host interface
show host interface brief
show host interface eth3
Router(config)# _
Router(hidden)# host interface eth3
Router(host-if-eth3)# no import
Router(host-if-eth3)# commit
help
exit
```

## 上下文幫�?

在任何模式、任何命令位置輸�?`?` 並按回車，會顯示當前位置可輸入的下一個命�?token 或參數：

```text
<Router> show ?
  interfaces  Show system interfaces
  version    Show software version

<Router> show interfaces ?
  brief  Show brief VVRP interface summary
  <name>  Show VVRP interface detail

<Router> show interfaces brief ?
  <cr>  Show brief VVRP interface summary
```

`show interfaces brief` uses a Huawei VRP-style interface summary format:
`Interface PHY Protocol InUti OutUti inErrors outErrors`.
`show interfaces` displays detailed VVRP interface information, including the VVRP IFNET Index in `0x` hexadecimal format.
`show host interface` is retained as a hidden/debug command family for inspecting host OS interfaces.
`shutdown` and `no shutdown` are interface-mode IFNET commands that apply the change to the OS network adapter. They usually require Administrator/root privileges. Loopback interfaces cannot be shut down.
Do not use `eth0` for destructive interface tests; use `eth3` in this workspace.

幫助文字來自命令註冊時的 `help_text`。如果下一�?token 是參數，例如 `<name:...>`，幫助也會自動沿用該完整命令�?`help_text`�?

`show` �?show 家族命令的父命令，會按當前模式列出該模式可用�?`show ...` 子命令�?

## 模式和提示符

| 模式 | 進入命令 | 提示�?|
|---|---|---|
| 一般模�?| 程序啟動時進入 | `<Router>` |
| 特權模式 | `enable` | `Router#` |
| 配置模式 | `config` | `Router(config)#` |
| 主機接口模式 | `host interface eth3` | `Router(host-if-eth3)#` |
| 隱藏模式 | `_` | `Router(hidden)#` |

`quit` 在特權模式、配置模式、接口模式和隱藏模式下可用，用於回到上一級模式；一般模式是最上層，不提供 `quit`，退出程序請使用 `exit`�?

隱藏入口 `_` 可以手動輸入執行，但不會出現�?`?`、`help` 或補全候選裡�?

命令不會無條件繼承上一級模式。每條命令都要通過 `modes=(...)` 明確註冊可用模式；如果一條命令只註冊�?`user` �?`privileged`，那它就只能在這兩個模式使用�?

## 擴展命令

```python
from src.CCmd import CommandRegistry, CommandResult

registry = CommandRegistry()

@registry.command(
    "show route <prefix:[0-9./]+>",
    help_text="Show a route entry",
    modes=("user", "privileged"),
)
def show_route(ctx, args):
    return CommandResult(message=f"route = {args['prefix']}")
```
