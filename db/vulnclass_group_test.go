package db

import (
	"strconv"
	"testing"
)

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

// TestFindingVulnClassGroupFilter protects the local canonical-group filter:
// different raw labels mapped to one parent group must be queried together,
// while an unknown group must return zero rather than silently degrading to
// "no filter". The raw vulnclass text itself must stay untouched.
func TestFindingVulnClassGroupFilter(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("类型分组筛选回归", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFindingsByTask(tk.ID)
	defer d.DeleteTask(tk.ID)

	rawLabels := []string{"XSS（分组回归）", "跨站脚本（分组回归）", "SQL 注入（分组回归）"}
	for _, raw := range rawLabels {
		if _, err := d.AddFinding(tk.ID, 0, raw, "n", "high", "s", "e", "w", nil); err != nil {
			t.Fatal(err)
		}
	}

	base := FindingFilter{TaskID: strconv.FormatInt(tk.ID, 10)}
	for group, want := range map[string]int{"XSS": 2, "SQL 注入": 1, "不存在的组": 0} {
		f := base
		f.VulnClassGroup = group
		_, total, err := d.ListFindingsPage(f, 1, 50)
		if err != nil {
			t.Fatalf("group %q: %v", group, err)
		}
		if total != want {
			t.Fatalf("group %q: want %d findings, got %d", group, want, total)
		}
	}

	var stored int
	if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1 AND vulnclass = ANY($2::text[])`, tk.ID, rawLabels).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != len(rawLabels) {
		t.Fatalf("raw vulnclass values must be preserved: want %d, got %d", len(rawLabels), stored)
	}
}
