# GeoServer 漏洞利用工具

一个简洁高效的 GeoServer 漏洞验证平台，提供图形化界面和多个常见漏洞的利用功能。
<img width="1434" height="1012" alt="image" src="https://github.com/user-attachments/assets/5114af24-a1cd-4ac3-9219-d0a7ec0ec837" />

## 功能模块

| 漏洞 | CVE | 功能 |
|------|-----|------|
| RCE 命令执行 | CVE-2024-36401 | 执行系统命令 |
| 内存马注入 | CVE-2024-36401 | 注入内存马 |
| XXE 注入 | CVE-2025-30220 | 文件读取和 SSRF |
| 反弹 Shell | CVE-2024-36401 | 交互式命令执行 |
| 文件读取 | CVE-2025-58360 | 读取服务器文件 |

## 快速开始

### 编译

```bash
go build
```

### 运行

```bash
./gui-exp.exe
```

## 使用方法

1. **选择漏洞模块**：左侧单选按钮选择要测试的漏洞
2. **输入参数**：在右侧输入框填入目标 URL 和对应参数
3. **执行验证**：点击"执行漏洞验证"按钮
4. **查看结果**：下方显示执行结果

## 功能特点

- 📱 简洁的图形化界面（基于 Fyne）
- 🔄 自动适配参数字段（切换模块时清空输入）
- 🌐 支持 HTTP 代理设置
- ⚡ 异步执行，无需等待

## 项目结构

```
.
├── main.go              # GUI 主程序
├── exploits/            # 漏洞模块
│   ├── rce.go
│   ├── inject.go
│   ├── xxe.go
│   ├── reverseshell.go
│   ├── filereading.go
│   └── httpclient.go
├── go.mod
└── README.md
```

## 技术栈

- **语言**：Go 1.21+
- **GUI**：Fyne v2.5.1
- **HTTP**：标准库 net/http

## 注意事项

- 仅用于授权的安全测试，违法使用后果自负
- 某些漏洞可能在新版本 GeoServer 中已修复
- 建议在隔离环境中测试
   - ✓ 实现 ExploitModule 元数据结构
   - ✓ 动态参数表单生成（根据选中模块显示不同字段）
   - ✓ Markdown 支持的详细描述面板
   - ✓ 异步执行和实时反馈

3. **代码清理**
   - ✓ 删除过时的导入（bytes, crypto/tls, encoding/base64 等）
   - ✓ 删除旧的 exploit2() 和 exploit() 函数
   - ✓ 统一按钮回调处理逻辑
   - ✓ 简化 proxySettingsWindow() 实现

### 核心函数说明

#### `formatTargetURL(input string) string`
- 功能：将用户输入的 URL 格式化为标准的 GeoServer WFS 端点
- 支持多种输入格式：IP、IP:PORT、完整 URL 等
- 返回：标准化后的目标 URL 或空字符串（格式错误）

#### `executeExploit(moduleName string, targetURL string, params []string) (string, error)`
- 功能：路由到对应的漏洞利用函数
- 参数检查和错误处理
- 返回：执行结果或错误信息

#### `proxySettingsWindow()`
- 功能：打开代理配置窗口
- 支持保存和清除代理设置
- 实时更新主窗口的代理标签

#### `main()`
- 功能：初始化 Fyne 应用和 GUI
- 组织左右两列布局
- 处理模块选择和参数动态更新

## 使用示例

### 命令执行

1. 选择 "RCE 命令执行"
2. 输入目标 URL：`http://192.168.1.100:8080`
3. 输入命令：`cat /etc/passwd`
4. 点击 "执行漏洞验证"

### 内存马注入

1. 选择 "内存马注入"
2. 输入目标 URL
3. 点击 "执行漏洞验证"
4. 使用提示的配置（JAVA_AES_BASE64, pass, key）访问 `/*` 路径

### XXE 注入

1. 选择 "XXE 注入"
2. 输入目标 URL
3. 输入恶意 XSD URL：`http://attacker.com/evil.xsd`
4. 点击 "执行漏洞验证"

### 反弹 Shell

1. 选择 "反弹 Shell"
2. 输入目标 URL
3. 输入攻击机 IP：`192.168.1.50`
4. 输入监听端口：`4444`
5. 在攻击机上开启监听：`nc -lvnp 4444`
6. 点击 "执行漏洞验证"

## 安全建议

⚠️ **免责声明**：本工具仅用于授权的渗透测试和安全研究。未经授权对他人系统进行测试是违法的。



