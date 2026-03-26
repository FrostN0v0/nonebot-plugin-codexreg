<!-- markdownlint-disable MD024 MD028 MD033 MD036 MD041 MD046 -->
<div align="center">
  <a href="https://v2.nonebot.dev/store"><img src="https://github.com/FrostN0v0/nonebot-plugin-template/blob/resources/NoneBotPlugin.svg" width="300"  alt="NoneBotPluginLogo"></a>
  <br>
</div>

<div align="center">

# nonebot-plugin-codexreg

_✨ plugin-codexreg ✨_

<a href="./LICENSE">
    <img src="https://img.shields.io/github/license/FrostN0v0/nonebot-plugin-codexreg.svg" alt="license">
</a>
<img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="python">
<a href="https://github.com/astral-sh/uv">
    <img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json" alt="uv">
</a>
<a href="https://github.com/astral-sh/ruff">
<img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json" alt="ruff">
</a>

</div>

## 📖 介绍

~~注册某 AI 平台账号以增长其日活量~~

> [!NOTE]
> 目前仅实现了 milky （发文件）
>
> 本来想用 alc 的，但目前 alc unimsg milky 的发文件有 bug，先手动 call api 发文件了
>
> 根据你要用的适配器，改一下发送文件的实现就行了

## ⚙️ 配置

请参考 [config.py](./nonebot_plugin_codexreg/config.py) 中的 `Config` 类进行配置

## 🎉 使用

`cx reg -r <num>` 注册对应数目的 cx 账号

会以 json 文件或压缩包的形式返回账号信息, 可直接上传至 cpa

> [!IMPORTANT]
> 务必配置好**家宽代理**，以提高成功率
>
> 至于**邮箱域名白名单**，也建议配置，否则部分域名邮箱可能会被拒绝注册
