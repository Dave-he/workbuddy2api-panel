// chat.go 把 /v1/chat/completions 的处理拆成清晰阶段，避免单函数膨胀（重构 #6）：
//
//	Handler.chatCompletions  — HTTP 薄入口：建 chatRun 并交给 run
//	chatRun.prepare          — 阶段 1：读 body、peek、会话键、提示词/model 改写、会话头
//	chatRun.rotate           — 阶段 2：选号轮转主循环（选号 → 上游 → 分类/处置 → 响应）
//	chatRun.pickAccount      — 阶段 2a：粘性/普通/跨域回退选号
//	chatRun.handleHTTPError  — 阶段 2b：非 2xx 的 fail-fast 分类（决定写回/换号/终止）
//	chatRun.serveStream      — 阶段 2c：流式成功路径透传 + 标记修复 + 记账
//	chatRun.serveAggregated  — 阶段 2d：非流式聚合 + 标记修复 + 记账
//	chatRun.finishError      — 阶段 3：轮转耗尽后的末端错误透传
//
// 纯机械拆分：控制流、判据与旧单函数逐行等价（HTTP 级测试与既有单测是护栏）。
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/prompt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/reqlog"
	"github.com/linguo2625469/workbuddy2api-panel/internal/session"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
	"github.com/linguo2625469/workbuddy2api-panel/internal/usage"
)

// chatRun 承载单次 /v1/chat/completions 请求在各阶段间共享的可变状态。
// 每个 HTTP 请求一个实例，无跨请求共享，字段无需加锁。
type chatRun struct {
	h *Handler
	w http.ResponseWriter
	r *http.Request

	// 入参与请求形态
	clientIP  string
	body      []byte
	peek      chatPeek
	st        *chatStat
	modelRate string

	// 路由解析
	realm         string
	bareModel     string
	realmExplicit bool
	crossRealm    bool

	// 会话
	sessKey     string
	turnKey     string
	stickyUID   string
	reqHasImage bool

	// 提示词降级
	degradedApplied bool

	// 出站会话头族（轮转内复用）
	chatMeta upstream.ChatMeta

	// 工具名名单（标记修复用；来自请求 tools 声明 + 历史消息）
	declaredTools map[string]bool

	// 轮转状态
	tried        map[string]bool
	lastErr      error
	modelBlock   pool.ModelBlockStatus
	heldUID      string
	stopRotation bool // WAF IP 级 / ctx 取消：终止轮转走末端透传，不再换号
}

// chatCompletions HTTP 薄入口：组装 chatRun，prepare 失败就地写回，否则进入轮转。
func (h *Handler) chatCompletions(w http.ResponseWriter, r *http.Request) {
	cr := &chatRun{h: h, w: w, r: r, tried: map[string]bool{}}
	// st 在 prepare 内创建（hidden-model 等拒绝路径也需要落一行流水），入口统一
	// defer，避免在 prepare 栈里提前打印（那会在轮转之前落出空行）。
	defer func() {
		if cr.st != nil {
			cr.st.done()
		}
	}()
	if !cr.prepare() {
		return
	}
	cr.rotate()
}

// prepare 阶段 1：请求解析与出站改写。返回 false 表示已写回响应（调用方应直接返回）。
func (cr *chatRun) prepare() bool {
	h, r, w := cr.h, cr.r, cr.w
	// 客户端 IP 提取（按请求传递到 ChatStream，不透传时 upstream 侧忽略）；
	// 消除早年共享字段方案的并发交叉污染（issue：ClientIP 竞态）。
	cr.clientIP = upstream.ExtractClientIP(r)
	// 请求体无大小上限（max_body_mb 已移除，对齐上游）：完整读入，超限类问题交由
	// 上游自然返回错误（其响应经既有错误分类链路透出，信息量更大）。#41 的截断
	// 防御语义保留在读错误路径——移除预拦截后，截断只可能来自客户端自己断流，
	// 读 body 出错就地 400，不把半截 JSON 喂上游 unmarshal 报 unexpected EOF 冤枉罚号。
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request", "read body: "+err.Error())
		return false
	}
	cr.body = body
	_ = json.Unmarshal(body, &cr.peek)

	// 工具名名单：上游在没有 tools 的请求里会把工具调用吐成原生标记文本
	// （见 upstream/dsml.go），修复层用它做严格判定。名单来自「本请求声明的 tools」
	// 与「会话历史里出现过的工具名」两个来源——实测 tools 声明会在中转环节丢失，
	// 只认前者会让修复层在最需要它的场景下失效。
	// 在提示词/模型名改写之前取（那些改写不动 tools / messages[].tool_calls 子树）。
	cr.declaredTools = upstream.ToolNamesFromPeek(cr.peek.Tools, cr.peek.Functions, cr.peek.Messages)

	// realm 前缀解析（D6）：model 名可能带 "[realm:]" 前缀。剥出 realm + bareModel，
	// bareModel 用于选号/粘性/出站 body 重写（前缀是网关侧路由协议，上游只认裸名）。
	// 裸名 → ("cn", 原串)，CN 现状零回归。
	cr.realm, cr.bareModel, cr.realmExplicit = resolveModelDetail(cr.peek.Model)
	if h.cfg.Upstream != nil {
		cr.modelRate = h.cfg.Upstream.ModelRate(cr.realm, cr.bareModel)
	}
	// 跨域回退（issue #135）：只有裸模型名 + 显式开启 pool.cross_domain_fallback 时生效。
	cr.crossRealm = !cr.realmExplicit && h.cfg.Pool.CrossDomainFallback()

	// 请求级统计：出口即打一行表格日志（任何路径都会走到）。
	cr.st = newChatStat(time.Now(), cr.peek.Model, cr.peek.Stream)
	if tr := requestTraceFrom(r); tr != nil {
		tr.stat = cr.st
		// 来源在 ServeHTTP 入口采集（此时才知道开关与请求头），此处转交给统计对象，
		// 让 stdout 流水行与归档事件共用同一份来源值，两处不会漂移。
		cr.st.clientIP, cr.st.userAgent = tr.clientIP, tr.userAgent
	}

	// models.hidden 黑名单：点名调用直接拒绝，不打上游、不占选号。
	// 与 /v1/models 的列表过滤对称（只藏列表不够，知道名字仍可硬调）。
	if _, hide := h.loadLive().HiddenModels[cr.realm+":"+cr.bareModel]; hide {
		writeOpenAIErrorHint(w, http.StatusBadRequest, "model_unavailable",
			"model is hidden by gateway configuration, try another model", "")
		cr.st.status = http.StatusBadRequest
		cr.st.outcome = reqlog.OutcomeHTTPError
		return false
	}

	// 会话粘性：从请求体提取会话键并解析绑定号（找不到/无效则 stickyUID 为空，走普通轮换）。
	// ExtractKey 与粘性开关解耦（issue #35 侧）：关闭粘性时会话头族的聚合主键仍按
	// 会话级（RequestIDForKey(sessKey)），不悄悄退化成轮级——提取本身与粘性无关。
	// 会话键 + 轮级键一次解析（此前 ExtractKey / TurnKey 各完整 unmarshal 一遍
	// body——长历史消息占请求体绝大部分，两趟全量扫描合并为一趟）。
	cr.sessKey, cr.turnKey = session.RequestKeys(body)
	if h.cfg.Session != nil && cr.sessKey != "" {
		// 按模型解析：绑定号在**当前模型**被 6004 限额时视为不可用 → 重新分配，
		// 而不是钉在限额号上反复失败（"限额后换不动号"的正解）。
		resolve := h.cfg.Session.ResolveForModel
		if h.cfg.Pool.StrategyForRealm(cr.realm) != pool.WeightedRandom {
			resolve = h.cfg.Session.LookupForModel
		}
		if uid, ok := resolve(cr.sessKey, cr.peek.Model); ok {
			cr.stickyUID = uid
		}
	}

	// turnKey 必须在下方 prompt.Rewrite 之前取（已在上方与 sessKey 一并解析）：
	// 改写会动 messages 内容，之后取会让键漂移。

	// gateway_hint 判定所需的请求形态（image_url part）：在改写前取（与 turnKey
	// 同理）。11133「模型不支持图片」指向的前提。
	cr.reqHasImage = hasImagePart(cr.peek)

	// 系统提示词改写（出站前、轮转前；每个请求一次）。
	//   - custom：用自有提示词替换客户端 system/developer（从源头消灭 system 指纹误报）。
	//   - append：开头连续 system/developer 块后插自有提示词，既有消息逐字不动
	//     （客户端项目规范/工具约定与网关提示词并用，issue #129）。
	//   - passthrough + 降级期：换 Degraded 中性提示词直达，不再先撞 400。
	//   - passthrough / append 非降级期：透传客户端原始 system（append 则再插一条网关 system）。
	// 降级裁决：append 在降级期退化为 replace（Rewrite(Degraded)）——append 带
	// 指纹原文重试是确定性再撞墙，replace 是一次性最小抢救（issue #129 设计 §4）。
	if h.cfg.PromptMode == "custom" && h.cfg.PromptText != "" {
		cr.body = prompt.Rewrite(body, h.cfg.PromptText)
	} else if h.cfg.PromptMode == "append" && h.cfg.PromptText != "" && !h.degrade.Active() {
		cr.body = prompt.Append(body, h.cfg.PromptText)
	} else if (h.cfg.PromptMode == "passthrough" || h.cfg.PromptMode == "append") && h.degrade.Active() {
		cr.body = prompt.Rewrite(body, prompt.Degraded)
		cr.degradedApplied = true
	}

	// outbound model 名重写为 bareModel（D6）：realm 前缀是网关侧路由协议，
	// 上游不认前缀（global 账号也请求裸模型名）。裸名时 bareModel==peek.Model 恒等。
	if cr.bareModel != cr.peek.Model {
		cr.body = rewriteModel(cr.body, cr.bareModel)
	}

	// 会话头族（issue #35）：后台按 X-Conversation-Request-ID（对话轮级）聚合请求，
	// 官方客户端一次 user send 内所有 tool call/重试/换号复用同一个 ID。此处**轮转
	// 循环外**生成一次，循环内每次出站原样复用 → 换号/重试/降级全部同 ID，后台不再
	// 碎片化（此前网关一个都不发，上游按 HTTP 请求逐条记账，同一对话几十上百个
	// RequestID）。构建规则见 buildChatMeta 注释。
	cr.chatMeta = cr.buildChatMeta()
	return true
}

// buildChatMeta 组装出站会话头族（ConversationID / ConversationRequestID / TraceID）。
//   - conversationID：直接用 sessKey（Equal 性见 ExtractKey）；
//   - conversationRequestID：入站 X-Conversation-Request-ID 透传优先，否则按
//     粘性 key 进程内稳定生成；粘性 key 也空时走轮级兜底（TurnKey/TurnRequestID），
//     无 user 消息时退化成本请求级随机——轮转内捕获一次即共享；
//   - messageID 在 ChatHeaders 内每条消息生成（消息级独立，无需外部可见）。
//
// ConversationID passes the client dialog id through. Clients that have none
// (Anthropic / Claude Code traffic) fall back to the session key, otherwise
// the upstream prompt_cache_key degrades into one constant per account and
// every client on that account ends up sharing a single, constantly evicted
// prefix-cache slot.
func (cr *chatRun) buildChatMeta() upstream.ChatMeta {
	r := cr.r
	meta := upstream.ChatMeta{ConversationID: cr.sessKey}
	if v := r.Header.Get("X-Conversation-Request-ID"); v != "" {
		meta.ConversationRequestID = v
	} else if cr.turnKey != "" && cr.sessKey != "" {
		// 轮级复合键：sessKey 入键防跨会话同轮文本互撞（#170 统一轮级）。
		meta.ConversationRequestID = session.TurnRequestID(cr.sessKey + ":" + cr.turnKey)
	} else if cr.turnKey != "" {
		// 无会话键客户端：纯轮级键（既有兜底语义不变，存量会话键值零漂移）。
		meta.ConversationRequestID = session.TurnRequestID(cr.turnKey)
	} else if cr.sessKey != "" {
		// 残留空态兜底（无 user 消息/无可签名内容）：会话级聚合，好于请求级随机。
		meta.ConversationRequestID = session.RequestIDForKey(cr.sessKey)
	} else {
		// 无会话键也无轮级键：请求级随机（轮转内捕获一次即共享）。
		meta.ConversationRequestID = session.TurnRequestID("")
	}
	meta.TraceID = r.Header.Get("X-Trace-ID")
	return meta
}

// release 在途租约（函数出口统一调用，含成功 return）。
func (cr *chatRun) release() {
	if cr.heldUID != "" {
		cr.h.cfg.Pool.Release(cr.heldUID)
		cr.heldUID = ""
	}
}

// unbindSticky 解绑当前会话粘性号（stickyUID 非空时）。幂等。
func (cr *chatRun) unbindSticky() {
	if cr.stickyUID != "" {
		cr.h.cfg.Session.Unbind(cr.sessKey)
		cr.stickyUID = ""
	}
}

// fail 轮转失败分支统一：释放租约 + 若失败号正是粘性号则解绑（下次请求重新分配）。
func (cr *chatRun) fail(uid string) {
	cr.release()
	if cr.stickyUID != "" && uid == cr.stickyUID {
		cr.unbindSticky()
	}
}

// recordAttempt 记录本跳 token 用量到 pool 台账与 usage 时序（成功/失败都调）。
// ttfb 仅流式有观测；非流式传 0 = 无观测，速率不扣减。显式入参而不是读 st.ttfb：
// 后者在流式分支里是**调用之后**才赋值的，靠顺序传递会让将来重排代码时静默把速率
// 算回旧的错口径。
func (cr *chatRun) recordAttempt(uid string, delta pool.TokenUsageDelta, credit float64, hasCredit bool, started time.Time, ttfb time.Duration) {
	h, st := cr.h, cr.st
	st.attempts++
	if delta.HasPromptTokens {
		st.promptTokens = delta.PromptTokens
	}
	if delta.HasCompletionTokens {
		st.completionTokens = delta.CompletionTokens
	}
	if delta.HasTotalTokens {
		st.totalTokens = delta.TotalTokens
	} else if delta.HasPromptTokens || delta.HasCompletionTokens {
		st.totalTokens = st.promptTokens + st.completionTokens
	}
	delta.Model = cr.bareModel
	if delta.Model == "" {
		delta.Model = cr.peek.Model
	}
	latency := time.Since(started)
	latencyMs := latency.Milliseconds()
	if latencyMs < 1 {
		latencyMs = 1
	}
	delta.HasLatencyMs = true
	delta.LatencyMs = latencyMs

	// HasCompletionTokens 是「本次有没有 token 观测」的独立判断，与速率怎么算
	// 无关，所以留在调用点；速率本身的边界（TTFB 缺失/超界）收在 tokensPerSecond。
	if delta.HasCompletionTokens {
		if tps, ok := tokensPerSecond(delta.CompletionTokens,
			time.Duration(latencyMs)*time.Millisecond, ttfb); ok {
			delta.HasTokensPerSecond = true
			delta.TokensPerSecond = tps
		}
	}
	h.cfg.Pool.RecordTokenUsage(uid, delta)

	// 用量时序记录。ok 以「上游是否给了 usage」判定：空 delta 意味着这次尝试
	// 没拿到任何 token 统计（传输错误 / >=400 / 解析失败），计为失败尝试。
	// 失败也计入请求数——否则重试放大在「用量」视图里看不见。
	if h.cfg.Usage != nil {
		realm := "cn"
		if a, ok := h.cfg.Pool.Status(uid); ok && a.Realm != "" {
			realm = a.Realm
		}
		h.cfg.Usage.Add(time.Now(), realm, uid, delta.Model, usage.Delta{
			PromptTokens:     delta.PromptTokens,
			HasPromptTokens:  delta.HasPromptTokens,
			CompletionTokens: delta.CompletionTokens,
			HasCompletion:    delta.HasCompletionTokens,
			TotalTokens:      delta.TotalTokens,
			HasTotal:         delta.HasTotalTokens,
			Credit:           credit,
			HasCredit:        hasCredit,
			HasCacheTokens:   st.hasCache,
			CacheHitTokens:   st.cacheHit,
			CacheMissTokens:  st.cacheMiss,
			ModelRate:        cr.modelRate,
			LatencyMs:        delta.LatencyMs,
			HasLatency:       delta.HasLatencyMs,
			TokensPerSecond:  delta.TokensPerSecond,
			HasTPS:           delta.HasTokensPerSecond,
		}, delta.HasTotalTokens || delta.HasCompletionTokens || delta.HasPromptTokens)
	}
}
