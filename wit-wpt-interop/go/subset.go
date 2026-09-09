// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

package interop

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// 本文件实现 C_agent ⊆ P_grants 的 subset 判定。这是 demo 的 scheme-specific
// 实现点：id 支持通配（*、**、{a,b}、[a-z]，段内匹配即可）、params 按 §9.4
// 递归子集。它不声称是 AIC-JWT 的通用算法，扩展点（按 scheme 定义）如下标
// "SUBSET-EXT" 标记。

// matchIDGlob 把 id 模式编译为锚定正则：
//   - -> [^/]*    （单段内任意字符）
//     **  -> .*       （跨段任意字符）
//     {a,b} -> (?:a|b)
//     [a-z] -> 保留字符类（只允许 [a-zA-Z0-9_-]）
//
// 实现要点：先按 '/' 分段，再对每段做匹配（段内匹配即可）；段数不同的情况
// 回退到整串匹配（此时 ** 仍可跨段）。Go 与 TS 共用同一套转换规则。
func matchID(pattern, id string) bool {
	if pattern == "" {
		return pattern == id
	}
	psegs := strings.Split(pattern, "/")
	isegs := strings.Split(id, "/")
	if len(psegs) == len(isegs) {
		for i := range psegs {
			re, ok := segmentRE(psegs[i])
			if !ok || !re.MatchString(isegs[i]) {
				return false
			}
		}
		return true
	}
	// SUBSET-EXT：段数不同时回退整串匹配（允许 ** 跨段）。
	re, ok := wholeRE(pattern)
	return ok && re.MatchString(id)
}

func segmentRE(seg string) (*regexp.Regexp, bool) {
	src, ok := globToRegex(seg)
	if !ok {
		return nil, false
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, false
	}
	return re, true
}

func wholeRE(pattern string) (*regexp.Regexp, bool) {
	// 与 segmentRE 相同转换，但允许 ** 跨段（已含）。
	return segmentRE(pattern)
}

func globToRegex(pat string) (string, bool) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		switch {
		case c == '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case c == '{':
			end := strings.IndexByte(pat[i:], '}')
			if end < 0 {
				return "", false
			}
			body := pat[i+1 : i+end]
			parts := strings.Split(body, ",")
			b.WriteString("(?:")
			for k, p := range parts {
				if k > 0 {
					b.WriteString("|")
				}
				alt, ok := altRE(p)
				if !ok {
					return "", false
				}
				b.WriteString(alt)
			}
			b.WriteString(")")
			i += end
		case c == '[':
			end := strings.IndexByte(pat[i:], ']')
			if end < 0 {
				return "", false
			}
			class := pat[i : i+end+1]
			if !validClass(class) {
				return "", false
			}
			b.WriteString(class)
			i += end
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String(), true
}

// altRE 处理 {a,b} 内的成分：字母数字与 *、**。
func altRE(p string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '*':
			b.WriteString("[^/]*")
		default:
			if validLiteralChar(p[i]) {
				b.WriteString(regexp.QuoteMeta(string(p[i])))
			} else {
				return "", false
			}
		}
	}
	return b.String(), true
}

func validLiteralChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
		c == '-', c == '_', c == '.', c == ':':
		return true
	}
	return false
}

// validClass 校验 [a-z]/[A-Z0-9_-] 形式的字符类，避免 Go/TS 正则分歧。
func validClass(class string) bool {
	if len(class) < 3 || class[0] != '[' || class[len(class)-1] != ']' {
		return false
	}
	inner := class[1 : len(class)-1]
	for i := 0; i < len(inner); i++ {
		if !validLiteralChar(inner[i]) && inner[i] != '-' && inner[i] != '^' {
			return false
		}
	}
	return true
}

// paramsSubset 递归 subset：
//
//	number：agent ≤ grant
//	array：agent 每个元素 ⊆ grant 某元素
//	object：grant 每个键在 agent 中存在且递归 ⊆
//	其它：精确相等。
func paramsSubset(agent, grant any) bool {
	switch g := grant.(type) {
	case nil:
		return true
	case float64:
		a, ok := number(agent)
		return ok && a <= g
	case string:
		a, ok := agent.(string)
		return ok && a == g
	case bool:
		a, ok := agent.(bool)
		return ok && a == g
	case []any:
		a, ok := agent.([]any)
		if !ok {
			return false
		}
		for _, ag := range a {
			covered := false
			for _, gr := range g {
				if paramsSubset(ag, gr) {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		}
		return true
	case map[string]any:
		a, ok := agent.(map[string]any)
		if !ok {
			return false
		}
		for k, gv := range g {
			av, ok2 := a[k]
			if !ok2 {
				return false
			}
			if !paramsSubset(av, gv) {
				return false
			}
		}
		return true
	default:
		// SUBSET-EXT：未知 grant 类型（int 等）按精确相等。
		return reflect.DeepEqual(agent, grant)
	}
}

// number 把数值型转为 float64（JSON 数字或 Go 的 int/int64/float64）。
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	}
	return 0, false
}

// capabilitySpecSubset 判定 agent 能力 ⊆ grant 能力（scheme 相等 + id 通配 + params subset）。
func capabilitySpecSubset(agent, grant Capability) bool {
	if agent.Scheme != grant.Scheme {
		return false
	}
	if !matchID(grant.ID, agent.ID) {
		return false
	}
	return paramsSubset(agent.Params, grant.Params)
}

// capabilitiesCovered 判定 agent 能力集 ⊆ grants 能力集；返回 (是否覆盖, 说明)。
// detail 含 "subset" 字样，供签发阶段拒绝原因引用。
func capabilitiesCovered(agent, grants []Capability) (bool, string) {
	for _, ac := range agent {
		covered := false
		for _, gr := range grants {
			if capabilitySpecSubset(ac, gr) {
				covered = true
				break
			}
		}
		if !covered {
			return false, fmt.Sprintf("subset: capability %s:%s not covered by any grant",
				ac.Scheme, ac.ID)
		}
	}
	return true, "subset ok"
}

// capabilityCoveredIn 判定单个请求能力 ⊆ entitlement。供策略钩子复用。
func capabilityCoveredIn(req Capability, entitlement []Capability) (bool, string) {
	return capabilitiesCovered([]Capability{req}, entitlement)
}

// knownConstraintTypes 是本 harness 已知约束（fail-closed：未知类型即拒）。
// SUBSET-EXT：按 scheme 扩展时在这里登记新的约束校验器。
var knownConstraintTypes = map[string]func(Constraint) error{
	"max_rows": func(c Constraint) error {
		n, ok := number(c.Params)
		if !ok || n < 0 {
			return fmt.Errorf("constraint max_rows requires a non-negative number")
		}
		return nil
	},
}

// ValidateConstraints fail-closed：任何未知/畸形约束都必须拒绝。
func ValidateConstraints(cs []Constraint) error {
	for _, c := range cs {
		fn, ok := knownConstraintTypes[c.Type]
		if !ok {
			return fmt.Errorf("unknown constraint type %q (fail-closed)", c.Type)
		}
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}
