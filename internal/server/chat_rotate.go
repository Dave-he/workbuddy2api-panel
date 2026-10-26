package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// rotate 阶段 2：选号轮转主循环。每跳：选号 → 占在途名额 → token 刷新 → 打上游 →
// 按结果分类（传输错误 / HTTP 错误 / 流式 / 非流式）。任何分支 return 都已释放租约
// （release/fail 或成功路径末尾）。轮转耗尽走到 finishError。
func (cr *chatRun) rotate() {
	h := cr.h
	// 在途租约：成功选中即占名额；函数出口（含成功 return 与 panic）统一释放。
	defer cr.release()

	for i := 0; i < h.cfg.MaxRotate; i++ {
		acct := cr.pickAccount()
		if acct == nil {
			cr.st.status = http.StatusServiceUnavailable
			// 记下"是不是模型级阻塞"。选号返回 nil 有两种完全不同的成因：
			//   (a) 池子真的没有可用号（账号级冷却/在途占满/积分保底）；
			//   (b) 号都在，但每个号都对这个模型处于模型级冷却（11102/11158/6004）。
			// 两者此前都报 no_healthy_account，导致「模型不可用」被读成「号全挂了」。
			// 取一次快照供末端错误构造区分（issue #102 附带发现 1）。
			cr.modelBlock = h.cfg.Pool.ModelBlockedForRealm(cr.bareModel, cr.realm)
			break
		}
		cr.st.uid = acct.UID
		// 同步昵称：请求流水行只写 uid8 时无法直观看是哪一号，昵称随本次选号带入日志行。
		cr.st.nick = acct.Nickname
		if cr.crossRealm && h.cfg.Upstream != nil && acct.Realm() != cr.realm {
			// 跨域回退命中：按实际服务域取积分倍率，用量/账本记的是真实域口径，
			// 而不是请求前缀声明的域。
			cr.modelRate = h.cfg.Upstream.ModelRate(acct.Realm(), cr.bareModel)
		}
		cr.tried[acct.UID] = true

		// 占用在途名额：Pick 已跳过满额账号，此处 CAS 兜底并发抢名额的竞态。
		if !h.cfg.Pool.Acquire(acct.UID) {
			// 若被抢的正是粘性号，立即解绑并回落普通轮换，避免下一轮仍撞同一个
			// 满载粘性号再浪费一次 PickByUID 往返（语义与 fail()/PickByUID-nil 的解绑一致）。
			if cr.stickyUID != "" && acct.UID == cr.stickyUID {
				cr.unbindSticky()
			}
			if !rotateBackoff(i, cr.r.Context()) {
				// 客户端已断连：换号重试无意义，终止轮转走末端错误透传。
				break
			}
			continue // 最后一个名额被并发抢走 → 换号
		}
		cr.heldUID = acct.UID

		// token 临近过期 → 先 refresh（失败冷却换号）
		if acct.NeedsRefresh(h.cfg.RefreshSkew) {
			if err := h.cfg.Upstream.RefreshToken(acct); err != nil {
				cr.lastErr = err
				var ue *upstream.Error
				if errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead {
					h.cfg.Pool.Disable(acct.UID, "refresh session dead")
				} else {
					h.cfg.Pool.NoteError(acct.UID)
				}
				cr.fail(acct.UID)
				if !rotateBackoff(i, cr.r.Context()) {
					break // ctx 取消：终止轮转（refresh 失败换号退避）
				}
				continue
			}
			if err := acct.SaveAtomic(); err != nil {
				// 刷新成功但落盘失败：下次启动会用旧 token，必须暴露
				log.Printf("ERR: [server] chat refresh acct=%s: save auth failed: %v", logfmt.Label(acct.UID, acct.Nickname), err)
			}
		}

		// 客户端 IP 按请求传递（PassthroughIP 开启时注入；消除共享字段竞态）。
		attemptStarted := time.Now()
		rc, status, respBody, terr := h.cfg.Upstream.ChatStreamContext(cr.r.Context(), acct, cr.body, cr.clientIP, cr.chatMeta)
		// 分类信封一次成型：upstream 已在错误路径返回 *upstream.Error（Kind +
		// Retry-After 头解析）。传输层错误（非 *Error）走抖动换号分支；防御分支
		// （terr 为 nil 但 status>=400，如 ErrNone 兜底）回落本地 Classify，双保险。
		var uerr *upstream.Error
		if errors.As(terr, &uerr) {
			status = uerr.Status
		}
		if uerr == nil && terr != nil {
			// handleTransportError 返回 true = 终止轮转（超时 / ctx 取消），走 finishError；
			// false = 已换号处置，继续下一跳。
			if cr.handleTransportError(acct, terr, attemptStarted, i) {
				break
			}
			continue
		}
		if status >= 400 {
			// 非 2xx：fail-fast 类立即写回；可换号类处置后 continue；stopRotation 跳出。
			if cr.handleHTTPError(acct, status, respBody, uerr, attemptStarted, i) {
				return
			}
			if cr.stopRotation {
				break
			}
			continue
		}
		// 成功判定与粘性绑定一律**延后到这一跳真正成功之后**（见流式/非流式分支）：
		// 上游「200 已开流 + 一帧 error」是真实形态（6004 限流、内容拦截、审核），
		// 此前在读第一帧之前就 NoteSuccess + 清 11102 负缓存 + 绑粘性 → 被限流的号
		// 记成健康、粘性把会话钉死在它身上，后续每一轮都打同一个限流号。
		if cr.peek.Stream {
			cr.serveStream(acct, rc, attemptStarted)
			return
		}
		cr.serveAggregated(acct, rc, attemptStarted)
		return
	}
	cr.finishError()
}

// pickAccount 选号：粘性号优先（PickByUIDForModel 已校验该模型可用性 + 在途未满），
// 否则按 realm 普通轮换（含跨域回退 issue #135）。
func (cr *chatRun) pickAccount() *auth.Auth {
	h := cr.h
	if cr.stickyUID != "" {
		acct := h.cfg.Pool.PickByUIDForModel(cr.stickyUID, cr.bareModel)
		// 跨域回退开启且请求为裸名时，粘性号可以落在任一域（回退成功后绑定的是另一域
		// 的账号，下一轮不该被 realm 校验立刻解绑）。
		if acct == nil || (cr.realm != "" && acct.Realm() != cr.realm && !cr.crossRealm) {
			// 粘性号在当前模型不可用（冷却/占满/该模型被 6004 限额）或 realm 不符 → 解绑，
			// 本次回落普通轮换。
			cr.unbindSticky()
			acct = nil
		}
		if acct != nil {
			return acct
		}
	}
	// 模型感知 + realm 感知选号：模型非空时启用 6004 模型级冷却豁免
	// （healthyForModel），realm 谓词过滤跨域账号。
	pickRealm := cr.realm
	if cr.crossRealm && h.cfg.Pool.ServableForModelRealm(cr.bareModel, cr.realm) == 0 &&
		h.cfg.Pool.ServableForModelRealm(cr.bareModel, otherRealm(cr.realm)) > 0 {
		// 首选域此刻没有真正可服务的号（11102 模型级负缓存 / 账号级冷却 /
		// 在途占满），而另一域有 → 直接换域选号（issue #135）。先看健康度再选，
		// 避免拿全冷却兜底捞回来的旧域账号白撞一次上游。
		pickRealm = otherRealm(cr.realm)
	}
	acct := h.cfg.Pool.PickExcludingForRealm(cr.tried, cr.bareModel, pickRealm)
	if acct == nil && cr.crossRealm {
		// 该域选不到（并发抢名额/轮换耗尽/另一域刚冷却完）→ 另一域再试一次，
		// 保持尽力而为语义；tried 已记录失败号，轮转仍由 MaxRotate 封顶。
		acct = h.cfg.Pool.PickExcludingForRealm(cr.tried, cr.bareModel, otherRealm(pickRealm))
	}
	return acct
}

// handleTransportError 处理上游传输层错误（非 *upstream.Error 的 terr）。
// 返回 true 表示已写回/终态（rotate 应 return）；false 表示已换号处置，调用方 continue。
// 注意：当前两条分支都通过 break/continue 由 rotate 控制，本方法把「终止轮转」编码为
// 返回 true（rotate 会走到 finishError），「已换号继续」编码为 false。
func (cr *chatRun) handleTransportError(acct *auth.Auth, terr error, started time.Time, i int) bool {
	h := cr.h
	// 上游超时 / 停滞：**不换号、不罚号**。
	//
	// 超时不是账号的问题：同一份请求换到别的号，撞上的是同一个慢上游，
	// 只会把客户端拖到 MaxRotate × header_timeout（部署值 600s 时最坏
	// 约半小时），期间还给一串健康号喂连败计数。此前全仓没有任何超时
	// 识别，超时和"网络抖动"共用同一条换号路径。
	//
	// 判定三态：net.Error.Timeout()（ResponseHeaderTimeout / Client.Timeout）、
	// 显式 deadline（DeadlineExceeded / os.ErrDeadlineExceeded）、以及
	// **客户端仍在但 ctx 被取消**——那只能是我们自己的空闲看门狗掐的流，
	// 也就是上游停滞。客户端主动断连时 r.Context() 已取消，走下面的抖动分支。
	if isUpstreamTimeout(terr, cr.r.Context().Err() != nil) {
		cr.recordAttempt(acct.UID, pool.TokenUsageDelta{}, 0, false, started, 0)
		cr.st.status = http.StatusServiceUnavailable
		cr.lastErr = fmt.Errorf("%w: %v", errUpstreamTimeout, terr)
		log.Printf("WARN: [server] upstream timeout acct=%s: %v (rotation stopped, account not penalized)",
			logfmt.Label(acct.UID, acct.Nickname), terr)
		cr.stopRotation = true
		return true // 终止轮转 → finishError（errUpstreamTimeout 有专门文案）
	}
	// 网络层抖动：只换号，不喂熔断计数（传输层错误对连续失败连坐熔断过于严苛）。
	// 连败兜底（issue #114）：喂连败计数——连不上上游是「不知道原因的失败」，
	// 连败 N 次临时出池，单次/偶发不罚（NoteFailures 内部达阈才动作）。
	// 上游 client 已打 transport error 日志。
	cr.recordAttempt(acct.UID, pool.TokenUsageDelta{}, 0, false, started, 0)
	cr.st.status = http.StatusServiceUnavailable
	cr.lastErr = terr
	h.cfg.Pool.NoteFailures(acct.UID)
	cr.fail(acct.UID)
	if !rotateBackoff(i, cr.r.Context()) {
		cr.stopRotation = true
		return true // ctx 取消：终止轮转
	}
	return false // 换号继续
}
