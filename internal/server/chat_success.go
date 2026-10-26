package server

import (
	"io"
	"log"
	"net/http"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/reqlog"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// serveStream 流式成功路径：透传 SSE + gateway_hint + 标记修复，结束后按结果
// （真成功 / error 帧 / 空流 / 客户端断连）处置账号、记用量与成本账本。
// 成功判定延后到「读完这一跳」之后：上游「200 已开流 + 一帧 error」是真实形态。
func (cr *chatRun) serveStream(acct *auth.Auth, rc io.ReadCloser, started time.Time) {
	h, w := cr.h, cr.w
	cr.st.status = http.StatusOK
	stats := newChatStatsReaderSince(rc, cr.st.start)
	// gateway_hint（SSE）：成功状态 200 已开流，中途 error 帧透传时附加
	// hint 字段（hintFn 惰性求值——正常流零开销，只有真撞到 error 帧才
	// 组装请求上下文做判定）。
	// errFrame：上游 error 帧原文（观察者旁路采集），用于流尾的账号处置。
	var errFrame string
	// 标记修复：上游在没有 tools 的请求里会把工具调用吐成原生标记文本，
	// 这里在透传前还原成 delta.tool_calls（见 upstream/dsml.go）。
	// 第二个参数为 true = 名单为空时启用弱判定——tools 声明在链路上丢失是
	// 实测最常见的泄漏成因，只做严格判定等于对主场景不设防。
	repair := upstream.NewMarkupRepair(cr.declaredTools, true)
	sErr := upstream.StreamHint(w, stats, upstream.FrameHintFunc(func() upstream.HintContext {
		return h.hintContext(cr.bareModel, cr.reqHasImage)
	}), upstream.WithErrorFrameObserver(func(payload string) { errFrame = payload }),
		upstream.WithMarkupRepair(repair))
	switch {
	case upstream.IsEmptyStreamError(sErr):
		// 上游 200 但空流（0 有效帧）：StreamHint 已写 error 帧 + [DONE]
		// 兜底（HTTP 头已发出只能 200），但这是上游缺陷不是成功——日志/
		// 状态收敛到 502 观测，与非流式 Aggregate 空流→502 upstream_parse
		// 同语义（此前 `_ =` 吞错把失败流记成 200，运维看到假成功）。
		// 只认 IsEmptyStreamError：客户端断连的写失败不误标（人已走，
		// 502 观测没有意义）。
		cr.st.status = http.StatusBadGateway
		cr.st.outcome = reqlog.OutcomeStreamError
		log.Printf("WARN: [server] stream acct=%s model=%s: empty upstream stream (200+0 frames)", logfmt.Label(acct.UID, acct.Nickname), cr.bareModel)
	case errFrame != "":
		// 上游以 error 帧报错（6004 限流 / 内容拦截 / 审核）：按帧内容分类并
		// 处置账号——**不记成功、不清 11102 负缓存、不绑粘性**。
		kind := upstream.FrameKind(errFrame)
		h.applyErrorPolicy(acct.UID, kind, errFrame, cr.bareModel, nil)
		cr.st.status = http.StatusServiceUnavailable
		cr.st.outcome = reqlog.OutcomeStreamError
		log.Printf("WARN: [server] stream acct=%s model=%s: upstream error frame kind=%s payload=%s",
			logfmt.Label(acct.UID, acct.Nickname), cr.bareModel, kind, logfmt.Truncate(errFrame, 200))
	case sErr != nil:
		// 客户端写失败（断连）：上游帧无恙，账号健康——账号侧照常记成功
		// （与 default 同语义），请求日志归为 Interrupted（人已走，未完成）。
		cr.st.outcome = reqlog.OutcomeInterrupted
		h.cfg.Pool.NoteSuccess(acct.UID)
		h.cfg.Pool.BlockModelClear(acct.UID, cr.bareModel)
		if cr.sessKey != "" && h.cfg.Session != nil {
			h.cfg.Session.Bind(cr.sessKey, acct.UID)
		}
	default:
		// 真成功：这一跳读完且上游没有报错，才记成功并让粘性跟上。
		cr.st.outcome = reqlog.OutcomeSuccess
		h.cfg.Pool.NoteSuccess(acct.UID)
		// 11102 负缓存清命：该账号该模型实测成功，立即解除避让（不必等 TTL 到期）。
		// BlockModelClear 按 "11102" reason 前缀识别，只清 11102 条目、不碰 6004 独立冷却。
		h.cfg.Pool.BlockModelClear(acct.UID, cr.bareModel)
		// 粘性跟随最终成功号：本轮成功的账号成为该会话的粘性绑定（覆盖旧绑定）。
		if cr.sessKey != "" && h.cfg.Session != nil {
			h.cfg.Session.Bind(cr.sessKey, acct.UID)
		}
	}
	credit, hasCredit := stats.Credit()
	if hit, miss, ok := stats.CacheTokens(); ok {
		cr.st.cacheHit, cr.st.cacheMiss, cr.st.hasCache = hit, miss, true
	}
	cr.recordAttempt(acct.UID, stats.Usage(), credit, hasCredit, started, stats.TTFB())
	// WARN 信号放 recordAttempt 之后：st.promptTokens 此时才是本次的观测值。
	if cr.st.hasCache {
		cacheMissWarn.noteCacheTokens(cr.bareModel, cr.st.promptTokens, cr.st.cacheHit, cr.st.cacheMiss)
	}
	if n := repair.Converted(); n > 0 {
		// 修复命中：上游本来会把工具调用吐成正文标记，这里已还原成 tool_calls。
		log.Printf("INFO: [server] stream acct=%s model=%s: repaired %d native tool call(s) from assistant text (tool names known=%d)",
			logfmt.Label(acct.UID, acct.Nickname), cr.bareModel, n, len(cr.declaredTools))
	} else if m := repair.Seen(); m > 0 {
		// 识别到标记却没还原：判定没过（工具名不合规 / 块内夹带正文 / 参数畸形）。
		log.Printf("WARN: [server] stream acct=%s model=%s: saw %d native tool call block(s) but repaired none (tool names known=%d)",
			logfmt.Label(acct.UID, acct.Nickname), cr.bareModel, m, len(cr.declaredTools))
	}
	cr.st.ttfb = stats.TTFB()
	// usage 缺失时保留 chatStat.toks 的 -1 哨兵（观测缺失 → 显示 "-"），
	// 不写入零值——否则「没观测到 usage」被伪造成「测得 0 token」，
	// 与非流式走 completionTokens 返回 -1 的口径不一致。
	if toks, hasUsage := stats.Tokens(); hasUsage {
		cr.st.toks = toks
	}
	// 成本账本：末帧 usage 带 credit 与 token 总数时记录实测单价，
	// 供下次选号把免费/便宜的号排在前面。
	if hasCredit {
		cr.st.credit = credit
		cr.st.hasCredit = true
		if total, tok := stats.TotalTokens(); tok && total > 0 {
			h.cfg.Pool.NoteModelCost(acct.UID, cr.bareModel, credit, total)
		}
	}
	rc.Close()
}

// serveAggregated 非流式成功路径：聚合上游响应 + 标记修复，写回 JSON 后记成功/
// 绑粘性/记成本。解析失败回 502。
func (cr *chatRun) serveAggregated(acct *auth.Auth, rc io.ReadCloser, started time.Time) {
	h, w := cr.h, cr.w
	resp, err := upstream.Aggregate(rc)
	rc.Close()
	if err != nil {
		cr.recordAttempt(acct.UID, pool.TokenUsageDelta{}, 0, false, started, 0)
		// 上游流解析失败：客户端还没看到任何输出，回 502 并告知原因。
		writeOpenAIError(w, http.StatusBadGateway, "upstream_parse", err.Error())
		cr.st.status = http.StatusBadGateway
		cr.st.outcome = reqlog.OutcomeHTTPError
		return
	}
	// 标记修复（非流式）：把正文里的原生工具调用标记还原成 message.tool_calls。
	// 只在「没有结构化 tool_calls」且「finish_reason 为 stop」时生效（见 dsml.go）；
	// 名单为空时走弱判定（tools 声明在中转环节丢失是常态）。
	mrepair := upstream.RepairAggregatedResponse(resp, cr.declaredTools, true)
	if n := mrepair.Converted(); n > 0 {
		log.Printf("INFO: [server] non-stream model=%s: repaired %d native tool call(s) from assistant text (tool names known=%d)",
			cr.bareModel, n, len(cr.declaredTools))
	} else if m := mrepair.Seen(); m > 0 {
		log.Printf("WARN: [server] non-stream model=%s: saw %d native tool call block(s) but repaired none (tool names known=%d)",
			cr.bareModel, m, len(cr.declaredTools))
	}
	credit, total, hasCredit := usageCreditTotal(resp)
	if u, ok := resp["usage"].(map[string]any); ok {
		if hit, miss, okC := cacheTokensFromUsage(u); okC {
			cr.st.cacheHit, cr.st.cacheMiss, cr.st.hasCache = hit, miss, true
		}
	}
	cr.recordAttempt(acct.UID, usageDeltaFromResponse(resp), credit, hasCredit, started, 0)
	if cr.st.hasCache {
		cacheMissWarn.noteCacheTokens(cr.bareModel, cr.st.promptTokens, cr.st.cacheHit, cr.st.cacheMiss)
	}
	writeJSON(w, http.StatusOK, resp)
	cr.st.status = http.StatusOK
	cr.st.outcome = reqlog.OutcomeSuccess
	cr.st.toks = completionTokens(resp)
	// 非流式同理：聚合成功（无 error 帧、非空流）才算这一跳成功，事后才记成功/绑粘性。
	h.cfg.Pool.NoteSuccess(acct.UID)
	h.cfg.Pool.BlockModelClear(acct.UID, cr.bareModel)
	if cr.sessKey != "" && h.cfg.Session != nil {
		h.cfg.Session.Bind(cr.sessKey, acct.UID)
	}
	// 成本账本（非流式）：从聚合响应的 usage 取 credit 与 token 总数。
	if hasCredit {
		cr.st.credit = credit
		cr.st.hasCredit = true
		h.cfg.Pool.NoteModelCost(acct.UID, cr.bareModel, credit, total)
	}
}
