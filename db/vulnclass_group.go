package db

import (
	"regexp"
	"strings"
	"unicode"
)

// VulnClassGroupOther 是未命中任何规则时的兜底分组。
const VulnClassGroupOther = "其他"

// vulnClassRule 按顺序匹配「归一化后」的原始漏洞类型文本。顺序很重要：
// 例如 Broken Access Control / 对象级授权缺失（BOLA）必须命中 BOLA/IDOR，
// 而不是更宽的访问控制分组。
type vulnClassRule struct {
	re    *regexp.Regexp
	group string
}

var vulnClassRules = []vulnClassRule{
	{regexp.MustCompile(`bola|idor|对象级授权|对象级权限|越权读取|越权访问|水平越权|越权对象引用|对象引用`), "BOLA/IDOR"},
	{regexp.MustCompile(`sql ?注入|sqli|盲注|sql injection`), "SQL 注入"},
	{regexp.MustCompile(`xss|跨站脚本|cross-site scripting`), "XSS"},
	{regexp.MustCompile(`ssrf|服务端请求伪造|server-side request forgery`), "SSRF"},
	{regexp.MustCompile(`xxe|xml ?外部实体|xml external entit`), "XXE"},
	// rce 必须是独立词：裸 rce 会误匹配 brute-force、enforcement、resource、source 等。
	{regexp.MustCompile(`\brce\b|远程代码执行|命令执行|代码执行|反序列化|deserial|模板注入|ssti|表达式注入|log4j|jndi|命令注入|command injection|code execution`), "RCE/命令执行"},
	{regexp.MustCompile(`文件上传|任意文件写入|upload|文件写入`), "文件上传"},
	{regexp.MustCompile(`路径穿越|目录穿越|任意文件读取|任意文件下载|path traversal|lfi|rfi|文件读取|文件包含|file inclusion|directory traversal`), "路径穿越/文件读取"},
	{regexp.MustCompile(`csrf|跨站请求伪造|cross-site request forgery`), "CSRF"},
	{regexp.MustCompile(`mfa|多因素|认证绕过|身份认证|认证缺陷|broken.?authentication|authentication (bypass|weakness)|弱口令|默认口令|默认凭据|weak credential|default credential|口令|密码重置|密码策略|session|会话|jwt|token|登录绕过|暴力破解|brute.?force|撞库|credential|验证码|captcha|人机验证|anti-automation|otp|2fa|签名校验|signature verification|user enumeration|账号枚举|unauthenticated account|account registration`), "认证/会话缺陷"},
	{regexp.MustCompile(`访问控制|权限校验|权限绕过|权限提升|垂直越权|越权|未授权访问|未授权|未鉴权|unauthenticated|unauthorized|broken access control|access control|authorization|authz|function.?level|missing function|preauthorize|maker.?checker|审批分离|权限缺失|role`), "访问控制缺陷"},
	// 注意：不能用裸的 log 关键字，否则 Business Logic 会被误判为信息泄露。
	{regexp.MustCompile(`信息泄露|敏感信息|information.?disclosure|数据泄露|泄露|exposure|openapi|swagger|api.?docs|源码|source code|日志泄露|保存日志|凭据泄露|密钥|secret|pii|隐私`), "敏感信息泄露"},
	{regexp.MustCompile(`业务逻辑|business logic|资金|佣金|提现|转账|订单|支付|费率|奖励|优惠|竞态|race condition|并发|重放|replay|库存|价格|返佣|结算|营销|优惠券|积分|余额|wallet|balance|transaction|approval`), "业务逻辑缺陷"},
	{regexp.MustCompile(`配置错误|misconfiguration|默认配置|调试|debug|actuator|spring boot admin|sba|管理端暴露|管理后台暴露|开放重定向|open redirect|cors|druid|暴露|exposed|审计|logging and monitoring|security logging`), "配置/审计缺陷"},
	{regexp.MustCompile(`拒绝服务|denial of service|dos|ddos|资源耗尽|zip bomb`), "拒绝服务"},
	{regexp.MustCompile(`注入|injection|ldap|xpath|crlf|header injection`), "其他注入"},
	{regexp.MustCompile(`加密|弱加密|tls|ssl|证书|certificate|crypto|哈希|hash|md5|sha1|随机数|random`), "加密/传输缺陷"},
}

// normalizeVulnClass 统一大小写/全角字符/下划线/空白，使同一类型的各种写法
// 能命中同一条规则。只做展示与分组用途，不修改数据库里的原始值。
func normalizeVulnClass(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E: // 全角 ASCII → 半角
			b.WriteRune(r - 0xFEE0)
		case r == 0x3000: // 全角空格
			b.WriteRune(' ')
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	s := strings.ReplaceAll(b.String(), "_", " ")
	s = strings.ToLower(s)
	return strings.Join(strings.Fields(s), " ")
}

// CanonicalVulnClass 把自由文本漏洞类型归一到稳定的父类型（如 BOLA/IDOR）。
// 同一父类型在统计、筛选和导出中都视为同一种漏洞；原始 vulnclass 保持不变。
func CanonicalVulnClass(raw string) string {
	n := normalizeVulnClass(raw)
	if n == "" {
		return VulnClassGroupOther
	}
	for _, rule := range vulnClassRules {
		if rule.re.MatchString(n) {
			return rule.group
		}
	}
	return VulnClassGroupOther
}

// applyVulnClassGroup 把 VulnClassGroup（父类型）展开成当前数据下所有对应的原始
// vulnclass 文本，供 where() 用 `= ANY(text[])` 精确筛选。组不存在时标记
// vulnClassMiss，让结果恒空而不是退化成不过滤。
func (d *DB) applyVulnClassGroup(f *FindingFilter) error {
	f.vulnClasses, f.vulnClassMiss = nil, false
	group := strings.TrimSpace(f.VulnClassGroup)
	if group == "" {
		return nil
	}
	rows, err := d.Query(`SELECT DISTINCT vulnclass FROM findings WHERE vulnclass <> ''`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var vc string
		if err := rows.Scan(&vc); err != nil {
			return err
		}
		if CanonicalVulnClass(vc) == group {
			f.vulnClasses = append(f.vulnClasses, vc)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(f.vulnClasses) == 0 {
		f.vulnClassMiss = true
	}
	return nil
}
