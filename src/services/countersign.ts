import type {
  ActorRole,
  CountersignPackage,
  CountersignPackageDecision,
  DecisionType,
  MergeConflict,
  MergePlanItem,
  MergePreview,
  MergeResolution,
  ReviewDecision,
  ThreatModelState,
} from '@/models/domain'
import { COUNTERSIGN_PACKAGE_FORMAT } from '@/models/domain'
import { decisionsForThreat } from '@/services/selectors'
import { createId } from '@/services/repository'

const VALID_ROLES: ActorRole[] = ['development', 'security', 'business']
const VALID_DECISIONS: DecisionType[] = [
  'accept',
  'degrade',
  'evidence_required',
  'approved',
  'rejected',
]

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null

/**
 * 导出当前会签包：只携带当前威胁修订号上的意见，
 * 旧修订号上已失效的意见不会随包导出。
 */
export const buildCountersignPackage = (
  state: ThreatModelState,
  exportedBy = '当前用户',
): CountersignPackage => {
  const threatRevision = new Map(state.threats.map((threat) => [threat.id, threat.revision]))
  const decisions: CountersignPackageDecision[] = state.decisions
    .filter((decision) => threatRevision.get(decision.threatId) === decision.revision)
    .map((decision) => ({
      id: decision.id,
      threatId: decision.threatId,
      role: decision.role,
      actor: decision.actor,
      decision: decision.decision,
      comment: decision.comment,
      createdAt: decision.createdAt,
      revision: decision.revision,
    }))

  return {
    format: COUNTERSIGN_PACKAGE_FORMAT,
    boundaryId: state.boundary.id,
    exportedAt: new Date().toISOString(),
    exportedBy,
    baseRevision: state.currentRevision,
    threats: state.threats.map((threat) => ({
      id: threat.id,
      code: threat.code,
      title: threat.title,
      revision: threat.revision,
      reviewStatus: threat.reviewStatus,
    })),
    decisions,
  }
}

const malformedConflict = (detail: string): MergeConflict => ({
  kind: 'malformed_package',
  title: '会签包格式无效',
  detail,
})

/**
 * 解析并校验回传包的基本结构；结构错误时返回的错误以
 * malformed_package 冲突列出，整包不得写入。
 */
export const parseCountersignPackage = (raw: string): { pkg?: CountersignPackage; error?: MergeConflict } => {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { error: malformedConflict('文件不是合法的 JSON，无法读取会签包。') }
  }
  if (!isRecord(parsed)) {
    return { error: malformedConflict('会签包内容不是对象结构。') }
  }
  if (parsed.format !== COUNTERSIGN_PACKAGE_FORMAT) {
    return {
      error: malformedConflict(
        `会签包格式标识为 "${String(parsed.format)}"，期望 ${COUNTERSIGN_PACKAGE_FORMAT}。`,
      ),
    }
  }
  if (typeof parsed.boundaryId !== 'string' || typeof parsed.exportedAt !== 'string') {
    return { error: malformedConflict('缺少边界标识或导出时间。') }
  }
  if (typeof parsed.baseRevision !== 'number') {
    return { error: malformedConflict('缺少版本基线号 baseRevision。') }
  }
  if (!Array.isArray(parsed.threats) || !Array.isArray(parsed.decisions)) {
    return { error: malformedConflict('缺少威胁清单或会签意见数组。') }
  }
  return { pkg: parsed as unknown as CountersignPackage }
}

const threatLabel = (state: ThreatModelState, threatId: string): string => {
  const threat = state.threats.find((item) => item.id === threatId)
  return threat ? `${threat.code} ${threat.title}` : threatId
}

const roleLabel = (role: ActorRole): string =>
  role === 'development' ? '开发负责人' : role === 'security' ? '安全负责人' : '业务负责人'

/**
 * 对回传包做合并预检（dry-run），不修改当前状态：
 * - 包级冲突：边界不一致、基线比当前更新（新修订号意见缺失，旧包不能套用）；
 * - 逐条冲突：威胁不存在、修订号过期、角色重复且结论不同、包内重复、枚举非法；
 * - 同角色同结论视为重复，跳过补入；同角色缺结论的角色才补入。
 */
export const previewMerge = (state: ThreatModelState, pkg: CountersignPackage): MergePreview => {
  const plan: MergePlanItem[] = []
  const conflicts: MergeConflict[] = []
  const packageConflicts: MergeConflict[] = []

  if (pkg.boundaryId !== state.boundary.id) {
    packageConflicts.push({
      kind: 'boundary_mismatch',
      title: '会签包来自其他建模边界',
      detail: `包边界 ${pkg.boundaryId} 与当前边界 ${state.boundary.id}（${state.boundary.name}）不一致。`,
    })
  }
  if (pkg.baseRevision > state.currentRevision) {
    packageConflicts.push({
      kind: 'future_revision',
      title: '回传包的版本基线更新',
      detail: `包基线为 v1.${pkg.baseRevision}，当前基线为 v1.${state.currentRevision}；新修订号的意见缺失，不能用旧基线状态套用新包。`,
    })
  }

  const threatMap = new Map(pkg.threats.map((threat) => [threat.id, threat]))
  const localThreatMap = new Map(state.threats.map((threat) => [threat.id, threat]))
  const seenKeys = new Set<string>()

  pkg.decisions.forEach((entry) => {
    const base: MergePlanItem = {
      decisionId: entry.id,
      threatId: entry.threatId,
      role: entry.role,
      actor: entry.actor,
      decision: entry.decision,
      comment: entry.comment,
      createdAt: entry.createdAt,
      revision: entry.revision,
      outcome: 'skip',
      note: '',
    }

    const fail = (conflict: MergeConflict): void => {
      plan.push({ ...base, outcome: 'conflict', note: conflict.title, conflict })
      conflicts.push(conflict)
    }

    if (!VALID_ROLES.includes(entry.role) || !VALID_DECISIONS.includes(entry.decision)) {
      fail({
        kind: 'invalid_decision',
        threatId: entry.threatId,
        title: '会签意见枚举非法',
        detail: `${entry.actor} 的角色或结论（${entry.role}/${entry.decision}）不在系统支持范围内。`,
      })
      return
    }

    const localThreat = localThreatMap.get(entry.threatId)
    if (!localThreat) {
      fail({
        kind: 'invalid_decision',
        threatId: entry.threatId,
        role: entry.role,
        title: '意见对应威胁不存在',
        detail: `当前基线中找不到威胁 ${entry.threatId}，无法并入 ${roleLabel(entry.role)}（${entry.actor}）的意见。`,
      })
      return
    }

    const key = `${entry.threatId}:${entry.role}`
    if (seenKeys.has(key)) {
      fail({
        kind: 'duplicate_in_package',
        threatId: entry.threatId,
        role: entry.role,
        title: '包内同一角色重复意见',
        detail: `${threatLabel(state, entry.threatId)} 的${roleLabel(entry.role)}在包中出现多条意见，系统要求同一角色只保留一条。`,
      })
      return
    }
    seenKeys.add(key)

    if (entry.revision > localThreat.revision) {
      fail({
        kind: 'future_revision',
        threatId: entry.threatId,
        role: entry.role,
        title: '意见基于更新的威胁修订号',
        detail: `${threatLabel(state, entry.threatId)}：${roleLabel(entry.role)}意见基于修订号 r${entry.revision}，当前为 r${localThreat.revision}，旧包不能覆盖新修订状态。`,
      })
      return
    }

    if (entry.revision < localThreat.revision) {
      fail({
        kind: 'stale_opinion',
        threatId: entry.threatId,
        role: entry.role,
        title: '威胁已重新修订，旧意见失效',
        detail: `${threatLabel(state, entry.threatId)}：${roleLabel(entry.role)}（${entry.actor}）意见基于 r${entry.revision}，当前修订号为 r${localThreat.revision}，旧修订意见不予合并。`,
      })
      return
    }

    const existing = decisionsForThreat(
      state.decisions,
      entry.threatId,
      localThreat.revision,
    ).find((decision) => decision.role === entry.role)

    if (existing) {
      if (existing.decision === entry.decision) {
        plan.push({
          ...base,
          outcome: 'skip',
          note: `本地已有相同结论（${entry.decision}），重复意见不补入。`,
        })
      } else {
        const conflict: MergeConflict = {
          kind: 'role_conflict',
          threatId: entry.threatId,
          role: entry.role,
          title: '同一角色重复意见，需重新确认',
          detail: `${threatLabel(state, entry.threatId)} 的${roleLabel(entry.role)}：本地结论为「${existing.decision}」（${existing.actor}），回传结论为「${entry.decision}」（${entry.actor}）。请重新确认通过或驳回，未确认前不合并。`,
        }
        plan.push({
          ...base,
          outcome: 'conflict',
          note: conflict.title,
          conflict,
        })
        conflicts.push(conflict)
      }
      return
    }

    const packagedThreat = threatMap.get(entry.threatId)
    if (packagedThreat && packagedThreat.revision !== entry.revision) {
      fail({
        kind: 'malformed_package',
        threatId: entry.threatId,
        role: entry.role,
        title: '意见修订号与包内威胁不一致',
        detail: `${threatLabel(state, entry.threatId)}：包内威胁修订号为 r${packagedThreat.revision}，但意见标记为 r${entry.revision}。`,
      })
      return
    }

    plan.push({
      ...base,
      outcome: 'apply',
      note: `本地缺少${roleLabel(entry.role)}意见，按 r${entry.revision} 补入。`,
    })
  })

  const resolvableConflicts = plan.filter(
    (item) => item.outcome === 'conflict' && item.conflict?.kind === 'role_conflict',
  )
  return {
    pkg,
    plan,
    conflicts,
    packageConflicts,
    resolvableConflicts,
    appliedCount: plan.filter((item) => item.outcome === 'apply').length,
    skippedCount: plan.filter((item) => item.outcome === 'skip').length,
  }
}

export const hasBlockingConflicts = (
  preview: MergePreview,
  resolutions: MergeResolution[],
): boolean => {
  if (preview.packageConflicts.length > 0) return true
  // 同角色重复意见只要负责人明确重新确认（保留本地或采用回传）即解除阻塞
  const decided = new Set(resolutions.map((item) => item.decisionId))
  return preview.plan.some(
    (item) =>
      item.outcome === 'conflict' &&
      !(item.conflict?.kind === 'role_conflict' && decided.has(item.decisionId)),
  )
}

const REQUIRED_ROLES: ActorRole[] = ['development', 'security', 'business']

export const recalcThreatStatus = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ThreatModelState['threats'][number]['reviewStatus'] => {
  const current = decisionsForThreat(decisions, threatId, revision)
  const allSubmitted = REQUIRED_ROLES.every((role) =>
    current.some((item) => item.role === role),
  )
  if (current.some((item) => item.decision === 'rejected')) return 'rejected'
  if (allSubmitted && current.every((item) => item.decision === 'approved')) return 'approved'
  return 'in_review'
}

export interface CommitMergeResult {
  decisionsAdded: number
  decisionsReplaced: number
}

/**
 * 在通过全部冲突校验后提交合并。调用方负责先做深拷贝，
 * 任何冲突未解决都不得调用本函数。
 */
export const commitMerge = (
  state: ThreatModelState,
  preview: MergePreview,
  resolutions: MergeResolution[],
): CommitMergeResult => {
  const incoming = new Set(
    resolutions
      .filter((item) => item.resolution === 'use_incoming')
      .map((item) => item.decisionId),
  )

  let decisionsAdded = 0
  let decisionsReplaced = 0

  preview.plan.forEach((item) => {
    if (item.outcome === 'apply') {
      state.decisions.unshift({
        id: createId('dec'),
        threatId: item.threatId,
        role: item.role,
        actor: item.actor,
        decision: item.decision,
        comment: item.comment,
        createdAt: item.createdAt,
        revision: item.revision,
      })
      decisionsAdded += 1
      return
    }
    if (
      item.outcome === 'conflict' &&
      item.conflict?.kind === 'role_conflict' &&
      incoming.has(item.decisionId)
    ) {
      state.decisions = state.decisions.filter(
        (decision) =>
          !(decision.threatId === item.threatId && decision.role === item.role && decision.revision === item.revision),
      )
      state.decisions.unshift({
        id: createId('dec'),
        threatId: item.threatId,
        role: item.role,
        actor: item.actor,
        decision: item.decision,
        comment: item.comment,
        createdAt: item.createdAt,
        revision: item.revision,
      })
      decisionsReplaced += 1
    }
  })

  const affectedThreatIds = new Set(
    preview.plan
      .filter(
        (item) =>
          item.outcome === 'apply' ||
          (item.outcome === 'conflict' &&
            item.conflict?.kind === 'role_conflict' &&
            incoming.has(item.decisionId)),
      )
      .map((item) => item.threatId),
  )
  affectedThreatIds.forEach((threatId) => {
    const threat = state.threats.find((item) => item.id === threatId)
    if (threat) {
      threat.reviewStatus = recalcThreatStatus(state.decisions, threat.id, threat.revision)
    }
  })

  return { decisionsAdded, decisionsReplaced }
}
