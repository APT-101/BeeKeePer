package db

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// =====================================================================
// 组件 DSL（IoT 固件组件搜索）
// =====================================================================
//
// 复用 asset_dsl.go 的通用解析机（Expr / astNode / dslParser / tok / readToken /
// isIdentStart / isIdentChar），组件专属的字段表、分词与 SQL 构建以 comp 前缀
// 自含 —— 两套 DSL 的字段表互不污染：资产搜索不认识组件字段，反之亦然，
// 避免跨表字段生成对不存在列的 SQL。
//
// 语法与资产 DSL 一致：field=value 模糊、field== 精确、field!= 排除、
// port>8080 数值比较、裸词全文模糊；AND/OR（大小写不敏感）与括号分组，
// AND 优先级高于 OR。

// compStringFields 组件 DSL 字符串字段 → SQL 列名。
// NOTE: "type" 刻意排除 —— 它是独立参数（与资产 DSL 的 type 参数同约定）。
var compStringFields = map[string]string{
	"component_name":  "component_name",
	"name":            "component_name",
	"version":         "version",
	"vendor":          "vendor",
	"binary":          "binary_path",
	"binary_path":     "binary_path",
	"config_path":     "config_path",
	"started_by":      "started_by",
	"status":          "status",
	"firmware_sha256": "firmware_sha256",
	"sha256":          "firmware_sha256",
}

// compArrayFields 组件 DSL 数组字段 → SQL 列名（数组）。
var compArrayFields = map[string]string{
	"technology":   "technologies",
	"technologies": "technologies",
	"tech":         "technologies",
}

// compNumericFields 组件 DSL 数字字段 → SQL 列名（整数）。
// 组件表当前只有 port 一个数字字段；保留引擎，后续加 size_bytes 之类可直接用。
var compNumericFields = map[string]string{
	"port": "port",
}

func compIsKnownField(f string) bool {
	f = strings.ToLower(f)
	_, s := compStringFields[f]
	_, a := compArrayFields[f]
	_, n := compNumericFields[f]
	return s || a || n || f == "company_id" || f == "task_id"
}

// compFullTextCols 裸词全文搜索的列。
var compFullTextCols = []string{
	"component_name", "version", "vendor", "binary_path", "config_path", "started_by", "notes",
}

// ── tokeniser（组件字段表感知；结构与 asset_dsl.go 的 tokenize 一致） ──────────

func compTryParseFieldExpr(s string, pos int) (Expr, int, bool) {
	i := pos
	if i >= len(s) || !isIdentStart(s[i]) {
		return Expr{}, pos, false
	}
	for i < len(s) && isIdentChar(s[i]) {
		i++
	}
	field := strings.ToLower(s[pos:i])
	if !compIsKnownField(field) {
		return Expr{}, pos, false
	}
	if i >= len(s) {
		return Expr{}, pos, false
	}
	var op string
	switch {
	case i+1 < len(s) && (s[i] == '=' || s[i] == '!' || s[i] == '>' || s[i] == '<') && s[i+1] == '=':
		op = s[i : i+2]
		i += 2
	case s[i] == '>' || s[i] == '<' || s[i] == '=':
		op = string(s[i])
		i++
	default:
		return Expr{}, pos, false
	}
	value, end := readToken(s, i)
	if end == i {
		return Expr{}, pos, false
	}
	return Expr{Field: field, Op: op, Value: value}, end, true
}

func compTokenize(s string) ([]tok, error) {
	var tokens []tok
	i := 0
	for i < len(s) {
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '(':
			tokens = append(tokens, tok{kind: tkLP})
			i++
		case ')':
			tokens = append(tokens, tok{kind: tkRP})
			i++
		default:
			if expr, end, ok := compTryParseFieldExpr(s, i); ok {
				tokens = append(tokens, tok{kind: tkField, expr: &expr})
				i = end
				continue
			}
			word, end := readToken(s, i)
			if word == "" {
				i++
				continue
			}
			switch strings.ToUpper(word) {
			case "AND":
				tokens = append(tokens, tok{kind: tkAnd})
			case "OR":
				tokens = append(tokens, tok{kind: tkOr})
			default:
				e := Expr{Field: "", Op: "=", Value: word}
				tokens = append(tokens, tok{kind: tkBare, expr: &e})
			}
			i = end
		}
	}
	tokens = append(tokens, tok{kind: tkEOF})
	return tokens, nil
}

// compParseDSL 解析组件 DSL 为表达式树（语法同 ParseDSL，字段表为组件字段）。
func compParseDSL(s string) (*astNode, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	tokens, err := compTokenize(s)
	if err != nil {
		return nil, err
	}
	p := &dslParser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tkEOF {
		return nil, fmt.Errorf("DSL 语法错误：意外的内容 '%s'", p.peek().kind)
	}
	return node, nil
}

// ── SQL builder ──────────────────────────────────────────────────────────────

type compWhereBuilder struct {
	args []any
	base int // 占位符从 base+1 起编号；0 = 常规 $1, $2, …
}

func (b *compWhereBuilder) next(v any) string {
	b.args = append(b.args, v)
	return fmt.Sprintf("$%d", b.base+len(b.args))
}

func (b *compWhereBuilder) build(node *astNode) (string, error) {
	switch node.kind {
	case "and":
		parts := make([]string, 0, len(node.children))
		for _, child := range node.children {
			clause, err := b.build(child)
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+clause+")")
		}
		return strings.Join(parts, " AND "), nil
	case "or":
		parts := make([]string, 0, len(node.children))
		for _, child := range node.children {
			clause, err := b.build(child)
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+clause+")")
		}
		return strings.Join(parts, " OR "), nil
	case "leaf":
		return b.buildLeaf(*node.expr)
	}
	return "", fmt.Errorf("unknown node kind: %s", node.kind)
}

func (b *compWhereBuilder) buildLeaf(e Expr) (string, error) {
	f := strings.ToLower(e.Field)

	// 裸词：全部文本列 + technologies 数组的 OR 模糊
	if f == "" {
		p := b.next("%" + e.Value + "%")
		var parts []string
		for _, col := range compFullTextCols {
			parts = append(parts, col+" ILIKE "+p)
		}
		parts = append(parts,
			"EXISTS (SELECT 1 FROM unnest(technologies) t(v) WHERE v ILIKE "+p+")",
		)
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}

	// task_id: $N = ANY(task_ids)
	if f == "task_id" {
		n, err := strconv.ParseInt(e.Value, 10, 64)
		if err != nil {
			return "", fmt.Errorf("task_id 需要整数值: %s", e.Value)
		}
		return b.next(n) + " = ANY(task_ids)", nil
	}

	// company_id: 精确整数
	if f == "company_id" {
		n, err := strconv.ParseInt(e.Value, 10, 64)
		if err != nil {
			return "", fmt.Errorf("company_id 需要整数值: %s", e.Value)
		}
		return "company_id = " + b.next(n), nil
	}

	// 数字字段
	if col, ok := compNumericFields[f]; ok {
		n, err := strconv.Atoi(e.Value)
		if err != nil {
			return "", fmt.Errorf("字段 %s 需要整数值: %s", f, e.Value)
		}
		op := e.Op
		if op == "==" {
			op = "="
		}
		if op != "=" && op != "!=" && op != ">" && op != ">=" && op != "<" && op != "<=" {
			return "", fmt.Errorf("字段 %s 不支持运算符 %s", f, e.Op)
		}
		return fmt.Sprintf("%s %s %s", col, op, b.next(n)), nil
	}

	// 数组字段
	if col, ok := compArrayFields[f]; ok {
		switch e.Op {
		case "==":
			return b.next(e.Value) + " = ANY(" + col + ")", nil
		case "!=":
			return "NOT (" + b.next(e.Value) + " = ANY(" + col + "))", nil
		case "=":
			p := b.next("%" + e.Value + "%")
			return "EXISTS (SELECT 1 FROM unnest(" + col + ") t(v) WHERE v ILIKE " + p + ")", nil
		default:
			return "", fmt.Errorf("数组字段 %s 不支持运算符 %s", f, e.Op)
		}
	}

	// 字符串字段
	if col, ok := compStringFields[f]; ok {
		switch e.Op {
		case "=":
			return col + " ILIKE " + b.next("%"+e.Value+"%"), nil
		case "==":
			return col + " = " + b.next(e.Value), nil
		case "!=":
			return col + " NOT ILIKE " + b.next("%"+e.Value+"%"), nil
		default:
			return "", fmt.Errorf("字符串字段 %s 不支持运算符 %s", f, e.Op)
		}
	}

	return "", fmt.Errorf("未知字段: %s", f)
}

func compBuildWhere(node *astNode) (string, []any, error) {
	return compBuildWhereBase(node, 0)
}

// compBuildWhereBase 是 compBuildWhere 的占位符偏移版：参数从 base+1 起编号，
// 给调用方留出 $1..$base（如 scope CTE 预留 $1 给任务 id）。
func compBuildWhereBase(node *astNode, base int) (string, []any, error) {
	if node == nil {
		return "1=1", nil, nil
	}
	b := &compWhereBuilder{base: base}
	clause, err := b.build(node)
	if err != nil {
		return "", nil, err
	}
	return clause, b.args, nil
}

// ValidateComponentDSL 解析并编译组件 DSL，不触库。HTTP 层用它区分客户端
// 语法错误与查询故障。
func ValidateComponentDSL(dsl string) error {
	node, err := compParseDSL(dsl)
	if err != nil {
		return err
	}
	_, _, err = compBuildWhere(node)
	return err
}

// ── 组件查询（方法挂在 ComponentStore 上，与 AssetStore 的 DSL 方法同名不冲突） ──

// componentSelectCols 是组件查询的公共 SELECT 前缀。
var componentSelectCols = "SELECT " + componentCols() + " FROM components"

// componentScopeTargetCTE 限定「本任务的组件」：task_ids 含 $1。
const componentScopeTargetCTE = `
target AS (
  SELECT id FROM components WHERE $1 = ANY(task_ids)
)`

// CountDSL 返回匹配 DSL 的组件总数（分页用）。taskID>0 时只统计该任务内的组件。
func (s *ComponentStore) CountDSL(dsl, typ, status string, taskID int64) (int, error) {
	node, err := compParseDSL(dsl)
	if err != nil {
		return 0, err
	}
	where, args, err := compBuildWhere(node)
	if err != nil {
		return 0, err
	}
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if taskID > 0 {
		args = append(args, taskID)
		where += fmt.Sprintf(" AND $%d = ANY(task_ids)", len(args))
	}
	var n int
	err = s.db.QueryRow("SELECT count(*) FROM components WHERE "+where, args...).Scan(&n)
	return n, err
}

// QueryDSL 执行组件 DSL 查询。typ/status 为可选过滤；taskID>0 时限定在该任务内。
func (s *ComponentStore) QueryDSL(dsl, typ, status string, taskID int64, limit, offset int) ([]*Component, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	node, err := compParseDSL(dsl)
	if err != nil {
		return nil, err
	}
	where, args, err := compBuildWhere(node)
	if err != nil {
		return nil, err
	}
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if taskID > 0 {
		args = append(args, taskID)
		where += fmt.Sprintf(" AND $%d = ANY(task_ids)", len(args))
	}
	args = append(args, limit, offset)
	q := componentSelectCols + " WHERE " + where +
		fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanComponents(rows)
	if err != nil {
		return nil, err
	}
	if taskID > 0 {
		if err := s.hydrateTaskComponentSources(taskID, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// QueryDSLInScope 是限定在「本任务组件」内的 QueryDSL（成员判定 = task_ids 含该任务）。
// taskID<=0 时退化为全局查询。
func (s *ComponentStore) QueryDSLInScope(dsl, typ, status string, taskID int64, limit, offset int) ([]*Component, error) {
	if taskID <= 0 {
		return s.QueryDSL(dsl, typ, status, 0, limit, offset)
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	node, err := compParseDSL(dsl)
	if err != nil {
		return nil, err
	}
	// $1 留给 taskID（scope CTE），DSL 占位符从 $2 起。
	where, dslArgs, err := compBuildWhereBase(node, 1)
	if err != nil {
		return nil, err
	}
	args := append([]any{taskID}, dslArgs...)
	if typ != "" {
		args = append(args, typ)
		where += fmt.Sprintf(" AND type = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}
	args = append(args, limit, offset)
	q := `WITH ` + componentScopeTargetCTE + ` ` + componentSelectCols +
		" WHERE " + where + " AND id IN (SELECT id FROM target)" +
		fmt.Sprintf(" ORDER BY last_seen DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanComponents(rows)
	if err != nil {
		return nil, err
	}
	if err := s.hydrateTaskComponentSources(taskID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetByIDsInScope 是限定在「本任务组件」内的 GetByIDs，越界 id 静默丢弃。
func (s *ComponentStore) GetByIDsInScope(taskID int64, ids []int64) ([]*Component, error) {
	if taskID <= 0 {
		return s.GetByIDs(ids)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, taskID)
	placeholders := make([]string, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	q := `WITH ` + componentScopeTargetCTE + ` ` + componentSelectCols +
		" WHERE id IN (" + strings.Join(placeholders, ",") + ")" +
		" AND id IN (SELECT id FROM target) ORDER BY last_seen DESC, id DESC"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanComponents(rows)
	if err != nil {
		return nil, err
	}
	if err := s.hydrateTaskComponentSources(taskID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// hydrateTaskComponentSources 填充每个组件的任务维度来源信息。
func (s *ComponentStore) hydrateTaskComponentSources(taskID int64, comps []*Component) error {
	if len(comps) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(comps))
	byID := make(map[int64]*Component, len(comps))
	for _, c := range comps {
		ids = append(ids, c.ID)
		byID[c.ID] = c
	}
	rows, err := s.db.Query(`SELECT component_id, source, source_summary, source_node_id
FROM task_component_links WHERE task_id=$1 AND component_id = ANY($2::bigint[])`, taskID, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var src, summary sql.NullString
		var node sql.NullInt64
		if err := rows.Scan(&id, &src, &summary, &node); err != nil {
			return err
		}
		if c, ok := byID[id]; ok {
			c.TaskSource = src.String
			c.TaskSourceSummary = summary.String
			if node.Valid {
				n := node.Int64
				c.TaskSourceNodeID = &n
			}
		}
	}
	return rows.Err()
}
