import type {
  ActorRole,
  CountersignPackage,
  CountersignPackageDecision,
  DecisionType,
  MergeConflict,
  MergePlanEntry,
  MergeResult,
  ReviewDecision,
  Threat,
  ThreatModelState,
} from '@/models/domain'

const PACKAGE_FORMAT_VERSION = 1
const VALID_DECISIONS: DecisionType[] = [
  'accept',
  'degrade',
  'evidence_required',
  'approved',
  'rejected',
]
const VALID_ROLES: ActorRole[] = ['development', 'security', 'business']

export const ROLE_LABELS: Record<ActorRole, string> = {
  development: '开发负责人',
  security: '安全负责人',
  business: '业务负责人',
}

export const DECISION_LABELS: Record<DecisionType, string> = {
  accept: '接受条件',
  degrade: '同意降级',
  evidence_required: '要求补证',
  approved: '通过',
  rejected: '驳回',
}

export const CONFLICT_LABELS: Record<MergeConflict['kind'], string> = {
  invalid_package: '包格式无效',
  unknown_threat: '威胁不存在',
  future_revision: '修订号超前',
  stale_revision: '旧修订意见已失效',
  invalid_decision: '意见格式无效',
}

/** 导出当前会签包：含模型版本号、逐条威胁修订号与当前会签意见。 */
export const buildCountersignPackage = (
  state: ThreatModelState,
  exportedBy: string,
): CountersignPackage => {
  const latestVersion = state.versions[0]
  const reviewThreatIds = new Set(
    latestVersion?.affectedThreatIds ?? state.threats.map((threat) => threat.id),
  )
  const threats = state.threats
    .filter((threat) => reviewThreatIds.has(threat.id))
    .map((threat) => ({
      id: threat.id,
      code: threat.code,
      title: threat.title,
      revision: threat.revision,
      reviewStatus: threat.reviewStatus,
    }))
  const threatIds = new Set(threats.map((threat) => threat.id))
  const decisions = state.decisions
    .filter((decision) => threatIds.has(decision.threatId))
    .map((decision) => ({ ...decision }))

  return {
    packageType: 'scapex-countersign-package',
    formatVersion: PACKAGE_FORMAT_VERSION,
    exportedAt: new Date().toISOString(),
    exportedBy,
    modelRevision: state.currentRevision,
    versionId: latestVersion?.id ?? '',
    versionLabel: latestVersion?.label ?? '未建立版本',
    threats,
    decisions,
  }
}

const isString = (value: unknown): value is string => typeof value === 'string' && value.trim().length > 0

/** 解析负责人回传的包文本；无法识别时返回错误信息。 */
export const parseCountersignPackage = (
  raw: string,
): { package?: CountersignPackage; error?: string } => {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { error: '不是合法的 JSON 文件，无法读取会签包。' }
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return { error: '会签包内容必须是 JSON 对象。' }
  }
  const candidate = parsed as Partial<CountersignPackage>
  if (candidate.packageType !== 'scapex-countersign-package') {
    return { error: '缺少包标识 packageType=scapex-countersign-package。' }
  }
  if (candidate.formatVersion !== PACKAGE_FORMAT_VERSION) {
    return {
      error: `包格式版本 ${String(candidate.formatVersion)} 不受支持（当前支持 v${PACKAGE_FORMAT_VERSION}）。`,
    }
  }
  if (typeof candidate.modelRevision !== 'number' || !Number.isFinite(candidate.modelRevision)) {
    return { error: '包中的版本号 modelRevision 缺失或不是数字。' }
  }
  if (!Array.isArray(candidate.threats) || !Array.isArray(candidate.decisions)) {
    return { error: '包中必须包含 threats 与 decisions 数组。' }
  }
  if (!isString(candidate.exportedAt)) {
    return { error: '包缺少导出时间 exportedAt。' }
  }
  return { package: candidate as CountersignPackage }
}

const validateDecision = (
  decision: CountersignPackageDecision,
  index: number,
): MergeConflict[] => {
  const where = `第 ${index + 1} 条意见`
  const conflicts: MergeConflict[] = []
  if (!isString(decision?.id)) conflicts.push({ kind: 'invalid_decision', message: `${where}：缺少意见编号。` })
  if (!isString(decision?.threatId)) conflicts.push({ kind: 'invalid_decision', message: `${where}：缺少威胁编号。` })
  if (!VALID_ROLES.includes(decision?.role)) {
    conflicts.push({ kind: 'invalid_decision', message: `${where}：会签角色 ${String(decision?.role)} 无效。` })
  }
  if (!VALID_DECISIONS.includes(decision?.decision)) {
    conflicts.push({
      kind: 'invalid_decision',
      message: `${where}：意见类型 ${String(decision?.decision)} 无效。`,
    })
  }
  if (!isString(decision?.actor)) conflicts.push({ kind: 'invalid_decision', message: `${where}：缺少会签人姓名。` })
  if (!isString(decision?.comment)) conflicts.push({ kind: 'invalid_decision', message: `${where}：缺少意见说明。` })
  if (typeof decision?.revision !== 'number' || !Number.isFinite(decision.revision)) {
    conflicts.push({ kind: 'invalid_decision', message: `${where}：威胁修订号缺失或不是数字。` })
  }
  if (!isString(decision?.createdAt) || Number.isNaN(Date.parse(decision.createdAt))) {
    conflicts.push({ kind: 'invalid_decision', message: `${where}：意见时间缺失或无法解析。` })
  }
  conflicts.forEach((conflict) => {
    conflict.decisionId = typeof decision?.id === 'string' ? decision.id : undefined
    if (isString(decision?.threatId)) conflict.threatId = decision.threatId
  })
  return conflicts
}

/**
 * 纯函数合并规划：逐条校验回传意见，返回冲突清单与待应用条目。
 * 任何冲突都表示必须整包回滚，调用方不得应用 plan。
 */
export const planMerge = (state: ThreatModelState, pkg: CountersignPackage): MergeResult => {
  const conflicts: MergeConflict[] = []
  const base: MergeResult = {
    ok: false,
    attemptedAt: new Date().toISOString(),
    source: {
      modelRevision: pkg.modelRevision,
      exportedAt: pkg.exportedAt,
      versionLabel: pkg.versionLabel ?? '未知版本',
      supplementOnly: pkg.modelRevision < state.currentRevision,
    },
    conflicts,
    entries: [],
    appliedCount: 0,
    replacedCount: 0,
    skippedCount: 0,
    affectedThreatIds: [],
  }

  // 回传包版本号超前于当前基线：拒绝合并
  if (pkg.modelRevision > state.currentRevision) {
    conflicts.push({
      kind: 'future_revision',
      message: `回传包基于 v1.${pkg.modelRevision}，当前中心基线仅 v1.${state.currentRevision}，请先升级基线再合并。`,
    })
    return base
  }
  const supplementOnly = pkg.modelRevision < state.currentRevision

  const threatMap = new Map<string, Threat>()
  state.threats.forEach((threat) => threatMap.set(threat.id, threat))

  // 同一包内同一(威胁,角色)重复意见：只保留时间最新的一条
  const deduped = new Map<string, CountersignPackageDecision>()
  pkg.decisions.forEach((decision, index) => {
    const decisionConflicts = validateDecision(decision, index)
    if (decisionConflicts.length > 0) {
      conflicts.push(...decisionConflicts)
      return
    }
    const key = `${decision.threatId}#${decision.role}`
    const existing = deduped.get(key)
    if (!existing || new Date(decision.createdAt).getTime() > new Date(existing.createdAt).getTime()) {
      deduped.set(key, decision)
    }
  })

  if (conflicts.length > 0) return base

  const entries: MergePlanEntry[] = []
  const affectedThreatIds = new Set<string>()

  deduped.forEach((decision) => {
    const threat = threatMap.get(decision.threatId)
    if (!threat) {
      conflicts.push({
        kind: 'unknown_threat',
        message: `意见 ${decision.id} 指向的威胁 ${decision.threatId} 在当前基线中不存在。`,
        threatId: decision.threatId,
        role: decision.role,
        decisionId: decision.id,
      })
      return
    }
    const threatCode = threat.code
    affectedThreatIds.add(threat.id)

    // 威胁修订更新后旧意见一律失效
    if (decision.revision < threat.revision) {
      conflicts.push({
        kind: 'stale_revision',
        message: `${threatCode} ${ROLE_LABELS[decision.role]} 的意见基于修订 r${decision.revision}，威胁已更新到 r${threat.revision}，旧意见失效，需在当前修订重新会签。`,
        threatId: threat.id,
        role: decision.role,
        decisionId: decision.id,
      })
      return
    }
    if (decision.revision > threat.revision) {
      conflicts.push({
        kind: 'future_revision',
        message: `${threatCode} ${ROLE_LABELS[decision.role]} 的意见修订号 r${decision.revision} 超前于当前 r${threat.revision}，无法合并。`,
        threatId: threat.id,
        role: decision.role,
        decisionId: decision.id,
      })
      return
    }

    const existing = state.decisions.find(
      (item) => item.threatId === decision.threatId && item.role === decision.role && item.revision === threat.revision,
    )
    if (existing) {
      // 较旧包只补缺失角色，不能覆盖新修订意见；同修订的重复意见需重新确认
      if (supplementOnly) {
        entries.push({
          decision,
          action: 'skipped',
          threatCode,
          note: `旧包（v1.${pkg.modelRevision}）仅补缺，${ROLE_LABELS[decision.role]}已有同修订意见，保留中心现有意见。`,
        })
        return
      }
      entries.push({
        decision,
        action: 'replaced',
        threatCode,
        note: `${ROLE_LABELS[decision.role]}重复意见，已用回传包中的重新确认意见替换。`,
      })
      return
    }
    entries.push({
      decision,
      action: 'added',
      threatCode,
      note: `${ROLE_LABELS[decision.role]}角色意见补齐。`,
    })
  })

  // 包中声明的威胁修订号也做一次交叉校验，防止篡改过威胁清单
  pkg.threats.forEach((packageThreat) => {
    const threat = threatMap.get(packageThreat.id)
    if (!threat) {
      conflicts.push({
        kind: 'unknown_threat',
        message: `包声明的威胁 ${packageThreat.id} 在当前基线中不存在。`,
        threatId: packageThreat.id,
      })
    } else if (packageThreat.revision > threat.revision) {
      conflicts.push({
        kind: 'future_revision',
        message: `${threat.code} 的包内修订号 r${packageThreat.revision} 超前于当前 r${threat.revision}。`,
        threatId: threat.id,
      })
    }
  })

  const result: MergeResult = {
    ...base,
    ok: conflicts.length === 0,
    conflicts,
    entries,
    appliedCount: entries.filter((entry) => entry.action === 'added').length,
    replacedCount: entries.filter((entry) => entry.action === 'replaced').length,
    skippedCount: entries.filter((entry) => entry.action === 'skipped').length,
    affectedThreatIds: [...affectedThreatIds],
  }
  return result
}

const REQUIRED_ROLES: ActorRole[] = ['development', 'security', 'business']

/** 合并完成后按当前修订三方意见重新确认威胁通过/驳回状态。 */
export const recalcReviewStatus = (
  decisions: ReviewDecision[],
  threat: Threat,
): Threat['reviewStatus'] => {
  const current = decisions.filter(
    (decision) => decision.threatId === threat.id && decision.revision === threat.revision,
  )
  if (current.some((decision) => decision.decision === 'rejected')) return 'rejected'
  const allSubmitted = REQUIRED_ROLES.every((role) => current.some((decision) => decision.role === role))
  if (allSubmitted && current.every((decision) => decision.decision === 'approved')) {
    return 'approved'
  }
  return 'in_review'
}
