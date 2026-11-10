package db

import "testing"

func TestCanonicalVulnClass(t *testing.T) {
	cases := map[string]string{
		"BOLA / 越权读取（对象级授权缺失）":                                               "BOLA/IDOR",
		"BOLA/IDOR (对象级授权缺失)":                                                "BOLA/IDOR",
		"BOLA/对象级授权缺失（越权读取）":                                                 "BOLA/IDOR",
		"Broken Access Control / 对象级授权缺失（BOLA）+ 返佣归属篡改":                      "BOLA/IDOR",
		"ＢＯＬＡ／越权访问":                                                          "BOLA/IDOR",
		"broken-authentication":                                              "认证/会话缺陷",
		"Broken Authentication / MFA bypass（验证码对象混淆）":                        "认证/会话缺陷",
		"认证缺陷 / MFA 校验无速率限制（Broken Authentication - MFA brute-force oracle）": "认证/会话缺陷",
		"missing_anti_automation / brute_force_protection":                   "认证/会话缺陷",
		"业务逻辑/客户端侧限制绕过 — 出金通道禁用标志与二次验证在提交面不生效（CWE-602 Client-Side Enforcement of Server-Side Security）": "业务逻辑缺陷",
		"存储型外部资源注入（Stored External Resource Injection / 客户端自动外连）":                                       "其他注入",
		"RCE / 反射调用（JNDI 注入 sink）": "RCE/命令执行",
		"未授权访问 / 不安全反射（任意 Spring bean 方法调用 + JNDI lookup，RCE 前奏；根因同 finding #196）": "RCE/命令执行",
		"information_disclosure":                                "敏感信息泄露",
		"Unauthenticated Access / Improper Access Control":      "访问控制缺陷",
		"Broken Access Control（功能级授权缺失 / role10 空权限 fail-open）": "访问控制缺陷",
		"SQL 注入": "SQL 注入",
		"SSRF":   "SSRF",
		"Business Logic / 内部转账二次验证缺失": "业务逻辑缺陷",
		"Spring Boot Admin 未授权实例注册":   "访问控制缺陷",
		"完全未知的分类":                     VulnClassGroupOther,
		"":                            VulnClassGroupOther,
	}
	for raw, want := range cases {
		if got := CanonicalVulnClass(raw); got != want {
			t.Errorf("CanonicalVulnClass(%q) = %q, want %q", raw, got, want)
		}
	}
}
