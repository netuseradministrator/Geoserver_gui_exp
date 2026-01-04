# GeoServer 综合漏洞利用平台

美化后的图形化界面工具，集成了多个 GeoServer 重要漏洞的利用功能。

## 功能特性

### ✨ 漏洞模块

1. **RCE 命令执行** (CVE-2024-36401)
   - 通过 WFS GetPropertyValue 参数执行任意系统命令
   - 原理：利用 ECQL 表达式引擎的 exec() 函数
   - 危害等级：⚠️ 严重

2. **内存马注入** (CVE-2024-36401 变体)
   - 通过 JavaScript 引擎在内存中注入恶意类
   - 配置：JAVA_AES_BASE64 加密，密码/密钥固定
   - 危害等级：⚠️ 严重（权限持久化）

3. **XXE 注入** (CVE-2025-30220)
   - 通过恶意 XSD 文件触发 XML 外部实体注入
   - 可用于文件读取、SSRF 或 RCE
   - 危害等级：⚠️ 高

4. **反弹 Shell**
   - 基于 RCE 建立交互式反向连接
   - 获得目标服务器命令行访问权
   - 危害等级：🔴 严重

### 🎨 GUI 特性

- **现代化界面设计**
  - 左侧面板：漏洞模块选择 + 详细描述
  - 右侧面板：参数输入 + 执行结果展示
  - 响应式布局，自动适配参数变化

- **元数据驱动的参数表单**
  - 自动根据选中模块调整输入字段
  - 动态显示参数提示和示例

- **代理支持**
  - 支持设置 HTTP 代理
  - 便于渗透测试场景下的流量监控

- **实时反馈**
  - 异步执行防止 UI 卡顿
  - 详细的状态和错误提示

## 项目结构

```
geoserver/
├── main.go                 # GUI 主程序和工具函数
├── exploits/               # 漏洞利用模块包
│   ├── httpclient.go      # HTTP 客户端封装
│   ├── rce.go             # 命令执行实现
│   ├── inject.go          # 内存马注入实现
│   ├── xxe.go             # XXE 利用实现
│   └── reverseshell.go    # 反弹 shell 实现
├── go.mod                  # Go 模块定义
├── go.sum                  # 依赖版本锁定
└── README.md              # 本文档
```

## 技术栈

- **语言**：Go 1.21+
- **GUI 框架**：Fyne v2.5.1
- **HTTP 客户端**：标准库 net/http
- **TLS**：支持 InsecureSkipVerify（用于自签名证书）

## 编译和运行

### 编译

```bash
cd geoserver
go build
```

生成可执行文件：`gui-exp.exe`

### 运行

```bash
./gui-exp.exe
```

## 代码重构清单

### ✅ 已完成

1. **模块化设计**
   - ✓ 将 5 个漏洞利用函数分离到独立文件
   - ✓ 创建 `exploits` 包，统一管理所有漏洞模块
   - ✓ 每个模块通过标准函数签名导出（接受 proxy *url.URL 参数）

2. **GUI 美化**
   - ✓ 删除所有旧的单一功能按钮
   - ✓ 设计现代化的两列布局（模块选择 + 参数输入）
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



