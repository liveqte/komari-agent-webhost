# komari-agent-webhost
使用解释型语言写的komari探针，适用于限制执行二进制探针的虚拟主机环境。
## 使用说明
## ⚙️ 命令行选项

| 参数 | 描述 |
|------|------|
| `--http-server <url>` | **服务器地址**（必须）。也可通过环境变量 `KOMARI_HTTP_SERVER` 设置 |
| `--token <token>` | **认证令牌**（必须）。也可通过环境变量 `KOMARI_TOKEN` 设置 |
| `--interval <sec>` | 实时数据上报间隔，单位为秒（默认：`1.0`）。可通过 `KOMARI_INTERVAL` 设置 |
| `--log-level <level>` | 日志级别：<br>0 = 关闭 Debug 日志<br>1 = 基本信息<br>2 = WebSocket 传输<br>3 = 终端日志<br>4 = 网络统计日志<br>5 = 磁盘统计日志 |
| `--disable-web-ssh` | 禁用远程控制功能（远程执行和终端） |
| `--help` | 显示帮助信息 |

## 🌱 环境变量配置

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `KOMARI_HTTP_SERVER` | 服务器地址（与 `--http-server` 参数对应） | 空字符串 |
| `KOMARI_TOKEN` | 认证令牌（与 `--token` 参数对应） | 空字符串 |
| `KOMARI_INTERVAL` | 实时数据上报间隔（秒）（与 `--interval` 参数对应） | `1.0` |
| `KOMARI_RECONNECT_INTERVAL` | WebSocket 重连间隔（秒） | `5` |
| `KOMARI_LOG_LEVEL` | 日志级别（与 `--log-level` 参数对应） | `0` |
| `KOMARI_DISABLE_REMOTE_CONTROL` | 是否禁用远程控制功能（`true` 表示禁用） | `false` |

## ⭐ 一百个 Stars 计划

大家好，我是这个项目的开发者。这个项目从零开始，一点点搭建、调试、优化，倾注了我很多心血。现在，我有一个小小的梦想 —— **希望这个项目能获得 100 个 Star**，以此作为申请免费 VPS 的凭证，继续为大家提供更稳定、更丰富的服务。

为了感谢大家的支持，我也准备了一些回馈计划：

- 🌟 **达到 50 个 Star**：我将升级项目中的 Node.js 版本，带来更好的性能和兼容性。
- 🌟 **达到 100 个 Star**：我将同步更新 PHP 版本，提升整体运行效率和安全性。

如果你觉得这个项目对你有帮助，或者你支持我的努力，请不吝点一个 Star ⭐。你的每一次点击，都是我继续前行的动力！

感谢每一位支持者 ❤️
## 致谢
https://github.com/GenshinMinecraft/komari-monitor-rs

https://komari-document.pages.dev/dev/agent.html
