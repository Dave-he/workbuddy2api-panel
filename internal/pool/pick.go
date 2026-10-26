// 选号：Pick 簇（healthy 成本分层 + 快过期虚拟实例权重 + 全冷却兜底 + 在途占满过滤）。
package pool

import (
	"log"
	"math/rand/v2"
	"sort"
	"strconv"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/logfmt"
)

// Pick 单一选号入口（无请求级轮换、无 realm 过滤，模型感知缺省账号级）。
// 需要请求级轮换（tried）或分池（realm）时用 PickExcludingForRealm。
func (p *Pool) Pick() *auth.Auth {
	return p.pick(nil, "", "")
}

// PickExcluding 同上，但跳过 tried 中的 uid（请求级轮换）。
// 挑选策略：healthy 账号中按权重取前 5 名，再在 Top5 内按同一权重加权随机抽签，
// 意图是打散热点，避免永远打同一个账号。
func (p *Pool) PickExcluding(tried map[string]bool) *auth.Auth {
	return p.pick(tried, "", "")
}

// PickExcludingForModel 模型感知选号：等同 PickExcluding，但对「6004 模型级冷却中的
// 账号」进行模型豁免——请求模型与其 trigger 模型不同时视为可用（issue #31）。
// reqModel 为空时即普通 PickExcluding（不影响既有调用语义）。
func (p *Pool) PickExcludingForModel(tried map[string]bool, reqModel string) *auth.Auth {
	return p.pick(tried, reqModel, "")
}

// PickExcludingForRealm 模型感知 + 分池选号：候选集先按 Realm()==realm 过滤
// （realm 空 = 不过滤，退化为 PickExcludingForModel），再按模型健康口径判定。
// 供 handler 在 global/cn 双域下分流（global 模型请求只路由 global 账号）。
func (p *Pool) PickExcludingForRealm(tried map[string]bool, reqModel, realm string) *auth.Auth {
	return p.pick(tried, reqModel, realm)
}

// pick 在 healthy 候选集中按权重加权随机选出账号，并记录 lastUsed（防并发撞号）。
// reqModel 非空时把健康口径换成 healthyForModel（6004 模型豁免生效）。
// realm 非空时候选过滤叠加 Realm()==realm 谓词（分池选号域）。
//
// 两阶段加锁（锁竞争优化，原实现全程独占写锁导致并发 pick 完全串行）：
//   - Phase 1（RLock，可并发）：遍历全部账号做健康/保底/在途过滤，算成本层与权重，
//     排序截断。这是每请求开销的大头（N 账号遍历 + O(n log n) 排序 + floorBlocked
//     回调上游 modelRateOf→effortsMu）。多个并发 pick 可同时执行；上游倍率查表在
//     RLock 下发出，不再出现「持 p.mu 写锁再跨包拿 effortsMu」的嵌套。
//   - Phase 2（短 Lock）：只做必须串行的探索判定与租约（exploreLast、lastUsed、
//     usedSeq、scheduling cursor），并复检候选未在 Phase 1 期间被其他 picker 标记；
//     竞争落败则用最新快照整轮重试一次，再落败返回 nil（由上层按既有重试处理）。
func (p *Pool) pick(tried map[string]bool, reqModel, realm string) *auth.Auth {
	now := time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		snap := p.collectCandidatesRLocked(tried, reqModel, realm, now)
		if len(snap.all) == 0 {
			// 全冷却兜底（有序策略等待恢复不提前试探仍在冷却中的账号）。
			return p.pickEarliestExpiry(tried, now, realm, reqModel, snap.strat)
		}
		if e, explored := p.leaseCandidate(snap, tried, reqModel, realm, now); e != nil {
			if explored {
				log.Printf("[pool] cost explore model=%s realm=%q acct=%s window=%s",
					reqModel, realm, logfmt.Label(e.a.UID, e.a.Nickname), p.costExploreInterval)
			}
			return e.a
		}
		// 租约竞争落败（候选在等锁期间被其他 picker 标记/占满）：重取快照再来。
	}
	return nil
}

// pickSnapshot 是 Phase 1（RLock）产出的只读候选快照：全部在锁内收集并排序，
// Phase 2 拿短锁后只复检，不再遍历全池。
type pickSnapshot struct {
	healthy    []*entry // 成本层过滤前的全部 healthy 候选（探索判定要 tier0/tier1 全集）
	all        []*entry // 成本层过滤后的生效层候选（加权路径按权重降序）
	top        []*entry // 加权抽签短名单（all 的前 5）
	ordered    []*entry // 有序策略候选快照；strat 非 WeightedRandom 时有效
	strat      string   // 本 realm 的策略
	maxCredits int64    // 全集（tier 过滤前全部 healthy）最大 credits，权重口径基准
}

// collectCandidatesRLocked 在 RLock 下完成 Phase 1：过滤 + 成本层 + 权重排序。
func (p *Pool) collectCandidatesRLocked(tried map[string]bool, reqModel, realm string, now time.Time) *pickSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	realmOK := func(e *entry) bool { return realm == "" || e.a.Realm() == realm }
	healthyOf := func(e *entry) bool { return realmOK(e) && e.healthy(now) }
	if reqModel != "" {
		healthyOf = func(e *entry) bool { return realmOK(e) && e.healthyForModel(now, reqModel) }
	}
	// floorBlocked 积分保底判定：可能回调上游 modelRateOf（内部拿 effortsMu）。
	// 只在 RLock 下调用——不再持 p.mu 写锁跨包拿上游锁。
	floorBlocked := func(e *entry) bool { return p.floorBlockedForRealmModel(e, reqModel, realm, now) }
	var healthy []*entry
	for uid, e := range p.byUID {
		if tried != nil && tried[uid] {
			continue
		}
		// 注意：过期模型冷却/成本台账的 prune 是写操作，不能放在 RLock 阶段。
		// 读取口径本身按时间戳跳过过期项（healthyForModel/modelCostOf），不 prune
		// 不影响本次选号正确性；真正删除延后到 Phase 2 短写锁内做（选中号 + 全量）。
		if !healthyOf(e) || floorBlocked(e) || p.inFlightFull(e) {
			continue
		}
		healthy = append(healthy, e)
	}
	snap := &pickSnapshot{strat: p.strategyForRealmLocked(realm)}
	if len(healthy) == 0 {
		return snap
	}
	// maxCredits 用**全集口径**（tier 过滤前的全部 healthy 候选）：截断排序与抽签
	// 权重共享同一基准，两个阶段权重可比。
	for _, e := range healthy {
		if e.credits > snap.maxCredits {
			snap.maxCredits = e.credits
		}
	}
	// 成本分层（reqModel 非空时）：
	//   0 = 已实测免费（限免期/夜间免费的号，最强偏好）
	//   1 = 无观测（含观测过期）
	//   2 = 已实测收费
	// 「无观测」排在「已实测收费」之前：新号限免状态只能靠实测发现，若已知收费号
	// 恒压未知号，免费号永远轮不到、永远学不到。硬过滤而非仅排序：否则加权随机
	// 仍会抽中收费号，达不到「优先免费」语义。
	costTier := func(e *entry) (int, float64) {
		mc, ok := e.modelCostOf(reqModel, now)
		if !ok {
			return 1, 0
		}
		if mc.CostPer1k <= 0 {
			return 0, 0
		}
		return 2, mc.CostPer1k
	}
	bestTier := 2
	for _, e := range healthy {
		if ti, _ := costTier(e); ti < bestTier {
			bestTier = ti
		}
	}
	// 权重只算一次：顶 5 截断要排序，若在比较器里现算 weightOf 会翻成 O(n log n)
	// 次冗余浮点计算。先 O(n) 预计算，再按 (cost1k, 权重, uid) 排序。
	type weighted struct {
		e      *entry
		w      float64
		cost1k float64
	}
	ws := make([]weighted, 0, len(healthy))
	for _, e := range healthy {
		ti, ci := costTier(e)
		if ti == bestTier {
			ws = append(ws, weighted{e: e, w: p.routingWeightOf(e, snap.maxCredits, now), cost1k: ci})
		}
	}
	if snap.strat != WeightedRandom {
		// 有序路径要求候选按 (accountOrder 排名, uid) 有序——pickOrderedLocked 内部
		// 也会排序，但 Phase 1 快照在 RLock 下收集（map 遍历随机序），必须先排好，
		// 否则持锁内的 selected=cands[0] 选择不稳定。
		sort.SliceStable(ws, func(i, j int) bool { return p.uidLessLocked(ws[i].e.a.UID, ws[j].e.a.UID, realm) })
		snap.ordered = make([]*entry, 0, len(ws))
		for _, w := range ws {
			snap.ordered = append(snap.ordered, w.e)
		}
		snap.all = snap.ordered
		snap.healthy = healthy
		return snap
	}
	// 等权重洗牌：仅当存在权重相等且候选数超过 top5 时做 Fisher-Yates（不消耗
	// p.randInt64N 注入源，避免改变加权抽签的确定性语义，
	// 见 TestPickDeterministicViaSetRandomSource）。按字典序截断会让 uid 靠后的等权
	// 账号永远进不了 top5（被饿死、惊群集中单号的根因）。
	if len(ws) > 5 {
		eq := false
		for i := 1; i < len(ws); i++ {
			if ws[i].w == ws[0].w {
				eq = true
				break
			}
		}
		if eq {
			shuf := rand.New(rand.NewPCG(uint64(now.UnixNano()), uint64(len(ws))))
			shuf.Shuffle(len(ws), func(i, j int) { ws[i], ws[j] = ws[j], ws[i] })
		}
	}
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].cost1k != ws[j].cost1k {
			return ws[i].cost1k < ws[j].cost1k // 收费层：单价低者在前
		}
		if ws[i].w != ws[j].w {
			return ws[i].w > ws[j].w
		}
		return ws[i].e.a.UID < ws[j].e.a.UID // 稳定兜底（洗牌后此项几乎不触发）
	})
	snap.all = make([]*entry, 0, len(ws))
	for _, c := range ws {
		snap.all = append(snap.all, c.e)
	}
	snap.healthy = healthy
	snap.top = snap.all
	if len(snap.top) > 5 {
		snap.top = snap.all[:5]
	}
	return snap
}

// leaseCandidate 在短写锁内完成 Phase 2：探索判定、候选复检、租约
// （lastUsed/usedSeq/cursor）与过期台账清理。返回的 explored 表示本次是否把生效层
// 切到了 tier 1（供调用方在锁外打探索事件日志）。
// 返回 e=nil 表示候选在等锁期间被其他 picker 标记/占满（调用方整轮重试）。
func (p *Pool) leaseCandidate(snap *pickSnapshot, tried map[string]bool, reqModel, realm string, now time.Time) (e *entry, explored bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 过期模型冷却/成本台账的惰性删除是写操作，只能在写锁阶段做（替代原实现
	// 「遍历时逐号 prune」）。map 有界（模型名数），每轮 pick 全量 prune 开销小。
	for _, en := range p.byUID {
		en.pruneExpiredModelCooldowns(now)
		en.pruneExpiredModelCosts(now)
	}

	ordered := snap.strat != WeightedRandom

	// 条件探索（issue #136 方案 a′）：tier 0 垄断 + tier 1 存在 + 距上次探索 ≥ 窗口
	// （零值 timer=从未探索→首次满足即探）时，本次生效层切 tier 1-only——探索=搭车
	// 改道，把一个既有真实用户请求改道给未知号（零新增上游请求，WAF 友好）。
	// 必须在写锁内判定并写 exploreLast：并发 pick 串行进入，只有一个能通过窗口判定
	// （天然防重复探索）。key=realm+"\x1f"+reqModel，节奏按 (域,模型) 独立。
	// 加权与有序策略都生效：有序路径把 explored 透传给 pickOrderedLocked，使其借用
	// tier 1 账号但不推进顺序耗尽主账号（主账号仍是免费的 tier 0 号）。
	if p.costExploreInterval > 0 && reqModel != "" {
		hasZero, hasTier1 := false, false
		for _, en := range snap.healthy {
			mc, ok := en.modelCostOf(reqModel, now)
			switch {
			case ok && mc.CostPer1k <= 0:
				hasZero = true
			case !ok:
				hasTier1 = true
			}
		}
		key := realm + "\x1f" + reqModel
		if hasZero && hasTier1 && now.Sub(p.exploreLast[key]) >= p.costExploreInterval {
			p.exploreLast[key] = now
			p.costExploreEvents++
			explored = true
		}
	}

	if ordered {
		cands := snap.ordered
		if explored {
			cands = p.tier1EntriesLocked(snap.healthy, reqModel, now, realm)
		}
		e = p.pickOrderedLocked(cands, tried, reqModel, realm, snap.strat, explored, now)
		if e != nil && p.inFlightFull(e) {
			return nil, false // 等锁期间被占满：整轮重试
		}
		if e != nil {
			p.markLeasedLocked(e, now)
		}
		return e, explored
	}

	top := snap.top
	if explored {
		top = p.tier1TopLocked(snap.healthy, reqModel, now, snap.maxCredits)
	}
	// 防并发撞号复检：minPickGap 窗口内用过、或等锁期间占满在途名额的号必须剔除。
	// lastUsed 在本锁内赋值，使时间窗口判定在并发下可重入。
	eligible := make([]*entry, 0, len(top))
	for _, c := range top {
		if now.Sub(c.lastUsed) >= minPickGap && !p.inFlightFull(c) {
			eligible = append(eligible, c)
		}
	}
	if len(eligible) == 0 {
		// top5 全部刚被用过/占满：LRU 兜底在**全候选**（非仅 top5）里选 usedSeq
		// 最旧者。usedSeq 单调序号而非墙钟：Windows ~0.5ms 精度下 lastUsed 会全等，
		// 严格全序与时间精度无关。
		e = snap.all[0]
		fallbackPool := snap.all
		if explored {
			fallbackPool = top // 探索生效时 LRU 也限定在 tier 1 子集内
			e = fallbackPool[0]
		}
		for _, c := range fallbackPool[1:] {
			// 已占满的号即便最旧也不能再压（Acquire 会拒绝，选了等于浪费一次轮换）。
			if !p.inFlightFull(c) && c.usedSeq < e.usedSeq {
				e = c
			}
		}
		if p.inFlightFull(e) {
			return nil, false // 全候选都占满：整轮重试（上层下一拍再看）
		}
	} else {
		e = p.pickWeighted(eligible) // eligible 保序 = top5 降序子集
	}
	p.markLeasedLocked(e, now)
	return e, explored
}

// markLeasedLocked 记录一次选中：即时标记 lastUsed（下一个 picker 立即看到本号已用），
// 并推进 pickSeq/usedSeq 单调序号（防惊群/LRU 的严格全序权威依据）。调用方持写锁。
func (p *Pool) markLeasedLocked(e *entry, now time.Time) {
	e.lastUsed = now
	p.pickSeq++
	e.usedSeq = p.pickSeq
}

// tier1TopLocked 在探索生效时从全候选取 tier 1（无观测）子集，按权重降序截断 top5。
// 调用方持写锁。
func (p *Pool) tier1TopLocked(all []*entry, reqModel string, now time.Time, maxCredits int64) []*entry {
	type tw struct {
		e *entry
		w float64
	}
	ws := make([]tw, 0, len(all))
	for _, en := range all {
		if _, ok := en.modelCostOf(reqModel, now); !ok { // tier 1 = 无观测
			ws = append(ws, tw{e: en, w: p.routingWeightOf(en, maxCredits, now)})
		}
	}
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].w != ws[j].w {
			return ws[i].w > ws[j].w
		}
		return ws[i].e.a.UID < ws[j].e.a.UID
	})
	top := make([]*entry, 0, 5)
	for _, c := range ws {
		top = append(top, c.e)
		if len(top) == 5 {
			break
		}
	}
	return top
}

// tier1EntriesLocked 在有序策略探索生效时，从全候选取 tier 1（无观测）子集并按
// (rank, uid) 排序（供 pickOrderedLocked 推进游标）。调用方持写锁。
func (p *Pool) tier1EntriesLocked(all []*entry, reqModel string, now time.Time, realm string) []*entry {
	out := make([]*entry, 0, len(all))
	for _, en := range all {
		if _, ok := en.modelCostOf(reqModel, now); !ok { // tier 1 = 无观测
			out = append(out, en)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return p.uidLessLocked(out[i].a.UID, out[j].a.UID, realm) })
	return out
}

// pickEarliestExpiry 全冷却兜底的两阶段外壳：RLock 下选「截止最早」的候选，
// 短 Lock 内复检并租约。分层：disabled 永不参与；CoolHard（余额耗尽等签到）同样
// 排除——调了必 402，浪费轮换并产生噪音；CoolSoft 与熔断号允许参与（可能已恢复，
// 失败成本仅一轮换）。有序策略等待恢复，不提前试探仍在冷却中的账号（返回 nil）。
// 被 tried 排除、在途占满、积分保底拦截的号同样跳过。无任何可用返回 nil。
func (p *Pool) pickEarliestExpiry(tried map[string]bool, now time.Time, realm, model, strat string) *auth.Auth {
	if strat != WeightedRandom {
		return nil // 有序策略等待恢复，不提前试探仍在冷却中的账号
	}
	// RLock 快探：是否存在任何符合兜底条件的冷却号。不存在则直接返回，不必升级写锁。
	p.mu.RLock()
	any := false
	for uid, e := range p.byUID {
		if tried != nil && tried[uid] {
			continue
		}
		if p.fallbackEligibleRLocked(e, tried, realm, model, now) {
			any = true
			break
		}
	}
	p.mu.RUnlock()
	if !any {
		return nil
	}
	// 短写锁内做最终选择与租约（持锁时长与原 pickEarliestExpiryLocked 同档）。
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *entry
	for uid, e := range p.byUID {
		if tried != nil && tried[uid] {
			continue
		}
		if !p.fallbackEligibleRLocked(e, tried, realm, model, now) {
			continue
		}
		exp := e.expiry(now)
		if best == nil || exp.Before(best.expiry(now)) {
			best = e
		}
	}
	if best == nil {
		return nil // 等锁期间最后一个候选也失效（回血/被禁用）
	}
	log.Printf("WARN: [pool] fallback_earliest_expiry acct=%s until=%s kind=%s",
		logfmt.Label(best.a.UID, best.a.Nickname), best.expiry(now).Format(time.RFC3339), best.fallbackKind(now))
	p.markLeasedLocked(best, now)
	return best.a
}

// fallbackEligibleRLocked 报告账号是否满足全冷却兑底候选条件（调用方持 p.mu 读/写锁）。
// 积分保底在此同样生效：floor 把 healthy 号全部拦掉后才走到兑底，若兑底不看保底，
// 触底号会被「撔回来」继续接收费模型（同一条 floor WARN 反复刷同一个号的实案）。
func (p *Pool) fallbackEligibleRLocked(e *entry, tried map[string]bool, realm, model string, now time.Time) bool {
	if realm != "" && e.a.Realm() != realm {
		return false // 域过滤：池内跨 realm 的冷却号不参与本 realm 兑底
	}
	if e.disabled || e.paused {
		return false // 禁用/暂停选号的号永不参与
	}
	if e.coolKind == CoolHard && !e.until.IsZero() && now.Before(e.until) {
		return false // 余额耗尽号（有效 hard 冷却期）不参与：等签到恢复，调了必 402
	}
	if p.floorBlockedForRealmModel(e, model, realm, now) {
		return false
	}
	if p.inFlightFull(e) {
		return false
	}
	return !e.expiry(now).IsZero()
}

// floorBlockedForModel 积分保底拦截判定（pick 普通轮换与 PickByUIDForModel 粘性
// 路径的单一事实来源）：floor>0 且账号触底（credits < floor）且该模型**收费**
// 时为真。
//
// 收费判据两级（任一成立即判收费 → 拦）：
//  1. 本地实测台账（e.modelCostOf）：该号在该模型上实测 cost>0（tier 2）。
//  2. 上游目录倍率（p.modelRateOf）：本地无观测/观测过期（tier 1）时的兜底。
//     只看实测会让「无观测」恒等于「放行」——而高价新模型恰恰全池无观测
//     （kimi-k3-1 实案：x1.62、223 分/百万 token，两笔打穿 100 分的号并触发
//     硬冷却到次日 04:00）。倍率由上游随模型目录下发，请求前即已知，不必付学费。
//
// 不拦的情形：
//   - 模型免费：本地实测 cost<=0（tier 0），或目录倍率为 0/"0.00"。保底的目的
//     正是「留余额给免费模型用」——但若账号已归零，上游仍会 402（余额门禁是
//     账号级的，与模型无关），此时由 ErrHardCredit 冷却承接，与本判定无关。
//   - 模型倍率未知（台账无观测且目录未下发该模型）：无法判收费，按放行处理。
//     这是有意的保守选择——目录未覆盖的模型多为内部/别名模型，拦了会让号
//     永久失联；风险由「未知」本身承担，但已知收费的一律拦。
//   - model 为空（无模型上下文）不拦：无成本维度，floor 无从判收费。
//
// 余额用本地插值口径（签到权威值 - 每笔 usage.credit 实扣，见 NoteModelCost）：
// 只会偏低不会偏高（官方对账延迟方向安全），正是保底需要的安全方向。
// 调用方必须已持有 p.mu（读 e.credits / e.modelCost / p.modelRateOf）。
func (p *Pool) floorBlockedForModel(e *entry, model string, now time.Time) bool {
	return p.floorBlockedForRealmModel(e, model, "", now)
}

// floorBlockedForRealmModel 同上，但带 realm 上下文（倍率按 (realm, 模型) 分桶，
// 同名模型在 CN / global 两域倍率可不同）。realm 为空时按倍率表的空域键查。
func (p *Pool) floorBlockedForRealmModel(e *entry, model, realm string, now time.Time) bool {
	if p.creditFloor <= 0 || model == "" || e.credits >= p.creditFloor {
		return false
	}
	// 1) 本地实测台账：最权威（真实扣费证据）。
	if mc, ok := e.modelCostOf(model, now); ok {
		return mc.CostPer1k > 0
	}
	// 2) 上游目录倍率兜底：无实测观测时用牌价判收费，堵住「无观测 = 放行」漏洞。
	if p.modelRateOf == nil {
		return false
	}
	rate := p.modelRateOf(realm, model)
	if rate == "" {
		return false // 目录未覆盖：未知，放行（见上方注释）
	}
	v, err := strconv.ParseFloat(rate, 64)
	if err != nil {
		return false // 倍率非数值（异常形态）：不据此惩罚账号
	}
	return v > 0
}

// inFlightFull 报告账号是否已占满在途名额（上限按 realm 分档，见 inFlightLimit；
// limit=0 不限 → 恒 false）。调用方需已持 p.mu（读锁或写锁均可，本方法只读上限）。
func (p *Pool) inFlightFull(e *entry) bool {
	limit := p.inFlightLimit(e)
	if limit <= 0 {
		return false
	}
	return e.inFlight.Load() >= int64(limit)
}

// minPickGap 防并发撞号窗口：同一账号在该窗口内不重复被选中（除非 top5 全部刚被用过）。
// 生产默认 100ms；纯加权分布测试可临时置 0 关闭防撞号。
var minPickGap = 100 * time.Millisecond

// pickWeighted 加权随机（claude-api selectWeightedRandom 参考口径）：
//
//		weight = credits 比例 × 10 + idleWeight
//
//	  - credits 比例 = 该号 credits / 候选集内最大 credits（避免量纲爆炸）
//	  - idleWeight = min(距 lastUsed 小时数 × idleWeightPerHour, idleWeightMax)；从未使用给满分
//
// credits 全 0 时仍按 idleWeight 加权（不退化均匀随机）。
// 权重为浮点，用 int64 定点（×1e6）抽签可保持确定性随机源注入（randInt64N 语义不变）。
// 随机源优先用 p.randInt64N（仅供测试注入确定性），nil 时回退 math/rand/v2 全局源。
func (p *Pool) pickWeighted(cands []*entry) *entry {
	now := time.Now()
	var maxCredits int64
	for _, e := range cands {
		if e.credits > maxCredits {
			maxCredits = e.credits
		}
	}
	const scale = 1_000_000 // 定点放大：int64 累加权重大整数抽签
	weights := make([]int64, len(cands))
	var total int64
	for i, e := range cands {
		w := p.routingWeightOf(e, maxCredits, now)
		weights[i] = int64(w * scale)
		total += weights[i]
	}
	rnd := rand.Int64N
	if p.randInt64N != nil {
		rnd = p.randInt64N
	}
	if total <= 0 {
		return cands[int(rnd(int64(len(cands))))]
	}
	r := rnd(total)
	var acc int64
	for i, e := range cands {
		acc += weights[i]
		if r < acc {
			return e
		}
	}
	return cands[len(cands)-1]
}

// weightOf 计算单个账号的普通加权分值。
func (p *Pool) weightOf(e *entry, maxCredits int64, now time.Time) float64 {
	w := 1.0
	// 1. credits 比例 ×10（会计入 mid-credit 锚点，避免全员 0 时 credits 项为 0）。
	if maxCredits > 0 {
		w += float64(e.credits) / float64(maxCredits) * 10
	}
	// 2. 闲置补偿。
	if e.lastUsed.IsZero() {
		w += p.idleWeightMax // 从未使用 → 满分
	} else {
		hours := now.Sub(e.lastUsed).Hours()
		idleW := hours * p.idleWeightPerHour
		if idleW > p.idleWeightMax {
			idleW = p.idleWeightMax
		}
		if idleW < 0 {
			idleW = 0 // lastUsed 在未来（时钟回拨）时钳 0
		}
		w += idleW
	}
	// 3.（原「成功率 ×3」因子已删，对齐上游 success-ema-review：errTotal 是终身
	// 累计、只增不减，成功率 = successCount/(successCount+errTotal) 会让早期出过错
	// 的号被永久压权且永不恢复；瞬时健康信号已由冷却/熔断/连败降权承接。）
	return w
}

// expiringNow 报告账号是否存在当前仍有效的快过期积分批次。
func expiringNow(e *entry, now time.Time) bool {
	return e.creditsExpiring > 0 &&
		e.creditsEarliestRemaining > 0 &&
		!e.creditsEarliestExpiry.IsZero() &&
		e.creditsEarliestExpiry.After(now)
}

// routingWeightOf 在普通账号权重上叠加快过期虚拟实例数量。prefer_expiring=false
// 或账号无有效快过期批次时，实例数恒为 1，结果与旧 weightOf 完全一致。
func (p *Pool) routingWeightOf(e *entry, maxCredits int64, now time.Time) float64 {
	w := p.weightOf(e, maxCredits, now)
	if p.preferExpiring && expiringNow(e, now) {
		return w * expiringVirtualSlots
	}
	return w
}
