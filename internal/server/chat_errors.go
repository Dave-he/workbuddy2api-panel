package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/prompt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/reqlog"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// handleHTTPError 处理一跳的非 2xx 响应。返回 true 表示已写回客户端（rotate 应
// return）；false 表示未写回，调用方按 decision 换号或终止轮转。
//
// 分类：
//   - 内容拦截误报（passthrough/append 首遇）→ 降级提示词同请求内重试（不罚号）；
//   - 内容防火墙 / prompt 过长 / 图片无效 / 参数非法 / 渠道满载 → 确定与账号无关，
//     立即透传上游原文，不轮转不罚号（避免把必然失败的请求伪装成 503 诱发无限重试）；
//   - 其余（限流/WAF/等）→ applyErrorPolicy 记账后换号；WAF IP 级激活时终止轮转。
func (cr *chatRun) handleHTTPError(acct *auth.Auth, status int, respBody []byte, uerr *upstream.Error, attemptStarted time.Time, i int) bool {
	h, w := cr.h, cr.w
	cr.recordAttempt(acct.UID, pool.TokenUsageDelta{}, 0, false, attemptStarted, 0)
	cr.st.status = status
	var kind upstream.ErrKind
	if uerr != nil {
		kind = uerr.Kind
	} else {
		kind = upstream.Classify(status, string(respBody))
		uerr = &upstream.Error{Kind: kind, Status: status, Msg: string(respBody)}
	}
	// 内容拦截误报（passthrough/append 模式首遇）：判定为 system 指纹误报，
	// 触发降级到次日 00:00 CST，换 Degraded 中性提示词同请求内重试（append
	// 降级重试同样退化为 replace——原文在场只会确定性再撞 400）。
	// 第二次仍被拦（用户内容本身触发审核）→ 回内容防火墙错误（见下分支）。
	// 内容问题非账号问题：applyErrorPolicy 不罚账号（见 ErrContentBlocked 分支）。
	if kind == upstream.ErrContentBlocked && (h.cfg.PromptMode == "passthrough" || h.cfg.PromptMode == "append") && !cr.degradedApplied {
		h.degrade.Trigger()
		cr.body = prompt.Rewrite(cr.body, prompt.Degraded)
		cr.degradedApplied = true
		delete(cr.tried, acct.UID) // 单账号池也能拿到重试机会（降级重试占一次名额）
		cr.release()
		return false // 同请求内用降级提示词重试（tried 已删，可能重取该号）
	}
	// 以下 fail-fast 类：确定与账号无关，立即透传不轮转。
	if d, ok := cr.failFastError(acct, kind, respBody, uerr); ok {
		writeOpenAIErrorHint(w, d.status, d.code, d.msg, d.hint)
		cr.st.status = d.status
		cr.st.outcome = reqlog.OutcomeHTTPError
		return true
	}
	// lastErr 携带完整 body（uerr.Msg 在 upstream 侧截断 200 字符，透传语义
	// 要求原文全量）+ Kind/RetryAfter（末端映射与冷却时长共用）。
	cr.lastErr = &upstream.Error{Kind: kind, Status: status, Msg: string(respBody), RetryAfter: uerr.RetryAfter}
	h.applyErrorPolicy(acct.UID, kind, string(respBody), cr.bareModel, uerr)
	cr.fail(acct.UID)
	// WAF IP 级 fail-fast（优先于 rotateBackoff 退避——IP 级拦截时退避无意义）：
	// 该次 WAF 403 喂入 IP 级状态机，若激活（短窗多号命中，IP 被拦而非账号）
	// 则立即终止轮转——继续换号只会把请求放大 MaxRotate 倍打同一出口 IP。账号级
	// 软冷却已在上方 applyErrorPolicy 照常记账。终止用 cr.stopRotation 标记，rotate
	// 读到后跳出循环（而非 continue 换号）。
	if kind == upstream.ErrWafBlock && h.wafIP.noteWaf(acct.UID) {
		cr.stopRotation = true
		return false
	}
	if !rotateBackoff(i, cr.r.Context()) {
		cr.stopRotation = true // ctx 取消：终止轮转
		return false
	}
	return false // 换号继续
}

// failFastError 判定「确定与账号无关」的错误并生成透传响应。ok=true 时 d 有效。
// 这些错误同一 body 换任何账号结果一致，轮转只会放大无效请求。
func (cr *chatRun) failFastError(acct *auth.Auth, kind upstream.ErrKind, respBody []byte, uerr *upstream.Error) (errorReply, bool) {
	h := cr.h
	body := string(respBody)
	hintFor := func(k upstream.ErrKind) string {
		return h.hintOf(k, body, cr.bareModel, cr.reqHasImage, uerr)
	}
	switch kind {
	case upstream.ErrContentBlocked:
		// 内容命中网关内容防火墙：不罚账号（applyErrorPolicy ErrContentBlocked 分支
		// 零动作）。message 装上游 body 原文（code/msg/requestId 原样）。
		h.applyErrorPolicy(acct.UID, kind, body, cr.bareModel, uerr)
		cr.fail(acct.UID)
		msg := body
		if strings.TrimSpace(msg) == "" {
			msg = "content blocked by upstream content firewall" // 空 body 兜底（不编造原文）
		}
		return errorReply{http.StatusBadRequest, "content_blocked", msg, hintFor(kind)}, true
	case upstream.ErrPromptTooLong:
		// 11115「prompt is too long」：message 装上游原文（含真实 token 数与上限）。
		h.applyErrorPolicy(acct.UID, kind, body, cr.bareModel, uerr)
		cr.fail(acct.UID)
		return errorReply{http.StatusBadRequest, "prompt_too_long", promptTooLongMessage(body), hintFor(kind)}, true
	case upstream.ErrImageInvalid:
		h.applyErrorPolicy(acct.UID, kind, body, cr.bareModel, uerr)
		cr.fail(acct.UID)
		msg := body
		if strings.TrimSpace(msg) == "" {
			msg = "image request was rejected by upstream"
		}
		return errorReply{http.StatusBadRequest, "image_invalid", msg, hintFor(kind)}, true
	case upstream.ErrBadParams:
		h.applyErrorPolicy(acct.UID, kind, body, cr.bareModel, uerr)
		cr.fail(acct.UID)
		msg := body
		if strings.TrimSpace(msg) == "" {
			msg = "chat request body was rejected by upstream"
		}
		return errorReply{http.StatusBadRequest, "bad_params", msg, hintFor(kind)}, true
	case upstream.ErrUpstreamBusy:
		// 6021「queue.full.title」渠道级容量满载：不罚号，503 + 可重试语义。
		h.applyErrorPolicy(acct.UID, kind, body, cr.bareModel, uerr)
		cr.fail(acct.UID)
		msg := body
		if strings.TrimSpace(msg) == "" {
			msg = "upstream capacity is full (queue.full); retry after a short wait"
		}
		return errorReply{http.StatusServiceUnavailable, "upstream_busy", msg, hintFor(kind)}, true
	}
	return errorReply{}, false
}

// errorReply 是 fail-fast 透传响应的四元组（状态码 / code / message / hint）。
type errorReply struct {
	status int
	code   string
	msg    string
	hint   string
}

// finishError 阶段 3：轮转耗尽后的末端错误透传（error-passthrough）。
// 上游返回的错误原样透传，不规范化成固定文案。本地调度类错误（无可用账号/传输
// 抖动/非上游 lastErr）保留自有 no_healthy_account 文案（不编造上游原文）。
func (cr *chatRun) finishError() {
	w := cr.w
	status := http.StatusServiceUnavailable
	code := "no_healthy_account"
	msg := "all accounts are temporarily unavailable, please retry later"
	// 上游超时：轮转已在传输层分支止损（见 isUpstreamTimeout），给一条能区分的文案，
	// 别混进"没有可用账号"——两者排查方向完全不同。
	if errors.Is(cr.lastErr, errUpstreamTimeout) {
		code = "upstream_timeout"
		msg = "upstream timed out: rotation stopped (another account would hit the same slow upstream), please retry later"
	}
	// gateway_hint（末端透传）：上游错误按 Kind + 原文 + 请求形态判定；本地调度类
	// 错误（无上游原文）固定 no_healthy_account hint。
	hint := upstream.NoHealthyAccountHint()
	// upstreamMsgPassed 记录 error.message 是否已被上游原文占据：模型级阻塞分支
	// 据此决定要不要覆盖 msg（上游原文优先，含 requestId）。
	upstreamMsgPassed := false
	var ue *upstream.Error
	if errors.As(cr.lastErr, &ue) {
		hint = cr.h.hintOf(ue.Kind, ue.Msg, cr.bareModel, cr.reqHasImage, ue)
		switch ue.Kind {
		case upstream.ErrSoftRate:
			status = http.StatusTooManyRequests
			code = "rate_limit_exceeded"
			msg = "rate limited: all accounts are cooling down, please wait a moment and try again"
		case upstream.ErrWafBlock:
			if cr.h.wafIP.active() {
				// IP 级拦截措辞（fail-fast 终止路径）：网关出口 IP 被 WAF 拦截、
				// 轮转已止损、窗口过后自动解除。客户端提前重试无意义（换号不换 IP）。
				code = "waf_ip_blocked"
				msg = "waf ip-level block: upstream firewall is blocking the gateway IP, rotation stopped; retry after the block window expires"
			}
		case upstream.ErrUpstreamBusy:
			code = "upstream_busy"
			msg = "upstream capacity is full (queue.full); retry after a short wait"
		case upstream.ErrModelBlocked:
			// 11102「该后端无此模型」：用 400 + 明确 code 把不可重试性质讲清楚，
			// 避免客户端据 503 无限重试（#81），真正该做的是换模型。
			code = "model_unavailable"
			status = http.StatusBadRequest
		}
		if s := strings.TrimSpace(ue.Msg); s != "" {
			msg = s // 上游原文优先：透传 code/msg/requestId，不拼接本地前缀。
			upstreamMsgPassed = true
		}
	}
	// 模型级阻塞覆盖上面的通用文案（最后 = 优先级最高）。
	//
	// 为什么能覆盖 code 而不丢信息：modelBlock.Reason 就是 BlockModelBackoff 存下的
	// 上游原因，已在 hint 里原样带出；覆盖 message 反而补上上游不会告诉客户端的
	// 两件事——「有几个号被挡」和「最早什么时候解封」。
	//
	// 用 400 而非 503：这是"你选的这个模型当前不可用"，不是"服务端暂时过载"。
	if cr.modelBlock.Blocked {
		code = "model_unavailable"
		if !upstreamMsgPassed {
			msg = "model is unavailable on every account (per-model cooldown), try another model"
		}
		hint = fmt.Sprintf("model_blocked: %d account(s) cooling down this model", cr.modelBlock.Count)
		if !cr.modelBlock.Until.IsZero() {
			hint += "; earliest unblock at " + cr.modelBlock.Until.Format(time.RFC3339)
		}
		if s := strings.TrimSpace(cr.modelBlock.Reason); s != "" {
			hint += "; upstream: " + s
		}
		status = http.StatusBadRequest
	}
	writeOpenAIErrorHint(w, status, code, msg, hint)
	cr.st.status = status
	cr.st.outcome = reqlog.OutcomeHTTPError
}
