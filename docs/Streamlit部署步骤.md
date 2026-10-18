# Streamlit Cloud 部署步骤（免费）

> 代码已推送到 GitHub，只需在网页点几下。

---

## 你的仓库地址

```
https://github.com/xsammzjs/ai-agent-toolchain-security
```

✅ **179 个文件已推送**，`.env` 密钥未上传（已在 .gitignore）

---

## 部署步骤（3 分钟）

### 第 1 步：打开部署页

```
https://share.streamlit.io
```

用 **GitHub 账号登录**（点 "Sign in with GitHub"）

---

### 第 2 步：授权

会跳到 GitHub 授权页 → 点 **Authorize streamlit**

---

### 第 3 步：填仓库信息

| 字段 | 填什么 |
|---|---|
| Repository | `xsammzjs/ai-agent-toolchain-security` |
| Branch | `main` |
| Main file path | `main.py` |

**点 Deploy。**

---

### 第 4 步：等待（首次 3-5 分钟）

Streamlit 会：
```
1. 安装 requirements.txt 里的依赖
2. 启动你的 main.py
3. 分配一个公网网址
```

完成后你会看到类似：
```
https://ai-agent-toolchain-security.streamlit.app
```

**那就是你的公网网址，任何人都能访问。**

---

## ⚠️ 云端环境说明

**云端不会有 `.env` 文件**，所以：

| 功能 | 云端表现 |
|---|---|
| 规则检测（29 条） | ✅ 完整可用 |
| 攻击链分析 | ✅ 完整可用 |
| 资产图谱 | ✅ 完整可用 |
| 依赖漏洞扫描 | ✅ 完整可用（需联网查 OSV/NVD） |
| AI 研判 | ⚠️ **降级为本地模板**，会明示"未调用大模型" |

**这是正常的。**云端演示主打规则引擎，不需要 AI 研判。

---

## 如果部署失败

| 报错 | 原因 | 解决 |
|---|---|---|
| `requirements` error | 依赖装不上 | 看日志，通常是版本问题 |
| `ModuleNotFoundError` | 依赖缺失 | 检查 requirements.txt |
| 一直 pending | 依赖安装慢 | 等 5 分钟 |

**把报错截图给我，我改代码。**

---

## ✅ 部署完成后

公网网址到手，可以：
- 放进作品报告「作品展示」栏
- 截图作为初赛材料
- 答辩时现场演示

---

**注意**：赛题要求的是「**华为云**上部署」，Streamlit 是免费的替代方案。
12 月拿到代金券后，再部署到华为云 ECS 满足赛题要求。
**两者不冲突，Streamlit 这份先用着。**