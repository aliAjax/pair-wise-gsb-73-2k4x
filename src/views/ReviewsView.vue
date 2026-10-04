<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ProgressBar from 'primevue/progressbar'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ActorRole,
  DecisionType,
  MergeConflict,
  MergePreview,
  MergeResolution,
  Threat,
} from '@/models/domain'
import { parseCountersignPackage } from '@/services/countersign'
import { decisionsForThreat, reviewProgress } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref('')
const decisionVisible = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)

const roleOptions: { label: string; value: ActorRole; actor: string }[] = [
  { label: '开发负责人', value: 'development', actor: '赵恺' },
  { label: '安全负责人', value: 'security', actor: '王岚' },
  { label: '业务负责人', value: 'business', actor: '宋雨' },
]
const decisionOptions = [
  { label: '通过', value: 'approved' },
  { label: '接受条件', value: 'accept' },
  { label: '同意降级', value: 'degrade' },
  { label: '要求补证', value: 'evidence_required' },
  { label: '驳回', value: 'rejected' },
]

const form = reactive<{
  role: ActorRole
  decision: DecisionType
  actor: string
  comment: string
}>({
  role: 'security',
  decision: 'approved',
  actor: '王岚',
  comment: '',
})

const latestVersion = computed(() => store.data.versions[0])
const affectedThreats = computed(() => {
  const ids = latestVersion.value?.affectedThreatIds ?? store.data.threats.map((threat) => threat.id)
  return store.data.threats.filter((threat) => ids.includes(threat.id))
})
const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedThreatId.value) ?? null,
)
const currentDecisions = computed(() =>
  selectedThreat.value
    ? decisionsForThreat(
        store.data.decisions,
        selectedThreat.value.id,
        selectedThreat.value.revision,
      )
    : [],
)

const statusForRole = (threat: Threat, role: ActorRole): DecisionType | 'pending' =>
  decisionsForThreat(store.data.decisions, threat.id, threat.revision).find(
    (decision) => decision.role === role,
  )?.decision ?? 'pending'

const openDecision = (): void => {
  if (!selectedThreat.value) return
  form.comment = ''
  form.role = 'security'
  form.actor = '王岚'
  form.decision = 'approved'
  decisionVisible.value = true
}

const changeRole = (): void => {
  form.actor = roleOptions.find((item) => item.value === form.role)?.actor ?? form.actor
}

const submitDecision = (): void => {
  if (!selectedThreat.value) return
  if (!form.comment.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '会签意见不能为空', life: 3000 })
    return
  }
  store.submitDecision(
    selectedThreat.value.id,
    form.role,
    form.decision,
    form.actor,
    form.comment,
  )
  decisionVisible.value = false
  toast.add({ severity: 'success', summary: '会签意见已提交', detail: '审核状态已重新计算', life: 2500 })
}

const decisionLabel = (decision: DecisionType | 'pending'): string =>
  decision === 'pending'
    ? '待提交'
    : decisionOptions.find((item) => item.value === decision)?.label ?? decision

const roleLabel = (role: ActorRole): string =>
  roleOptions.find((item) => item.value === role)?.label ?? role

const conflictKindLabel = (kind: MergeConflict['kind']): string =>
  ({
    malformed_package: '包格式无效',
    boundary_mismatch: '边界不一致',
    future_revision: '版本超前',
    stale_opinion: '旧意见失效',
    role_conflict: '角色重复冲突',
    duplicate_in_package: '包内重复',
    invalid_decision: '意见无效',
  })[kind]

const threatLabel = (threatId: string): string => {
  const threat = store.data.threats.find((item) => item.id === threatId)
  return threat ? `${threat.code} ${threat.title}` : threatId
}

const exportPackage = (): void => {
  const blob = new Blob([store.exportCountersignPackage()], {
    type: 'application/json;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `会签包-${store.data.boundary.name}-v1.${store.data.currentRevision}.json`
  anchor.click()
  URL.revokeObjectURL(url)
  toast.add({ severity: 'success', summary: '会签包已导出', detail: '包内含版本基线、威胁修订号与当前意见', life: 3000 })
}

const mergeVisible = ref(false)
const mergePreview = ref<MergePreview | null>(null)
const resolutions = reactive<Record<string, RoleResolutionChoice>>({})

type RoleResolutionChoice = 'keep_local' | 'use_incoming' | ''
const resolutionOptions = [
  { label: '保留本地意见（驳回回传）', value: 'keep_local' },
  { label: '采用回传意见（重新确认）', value: 'use_incoming' },
]

const triggerImport = (): void => {
  fileInput.value?.click()
}

const onPackageFile = async (event: Event): Promise<void> => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  const raw = await file.text()
  const parsed = parseCountersignPackage(raw)
  if (parsed.error || !parsed.pkg) {
    toast.add({
      severity: 'error',
      summary: '合并失败，整包未写入',
      detail: parsed.error?.detail ?? '无法解析会签包',
      life: 5000,
    })
    return
  }
  mergePreview.value = store.inspectCountersignPackage(parsed.pkg)
  Object.keys(resolutions).forEach((key) => delete resolutions[key])
  mergePreview.value.resolvableConflicts.forEach((item) => {
    resolutions[item.decisionId] = ''
  })
  mergeVisible.value = true
}

const hardConflicts = computed<MergeConflict[]>(() => {
  if (!mergePreview.value) return []
  return mergePreview.value.conflicts.filter((conflict) => conflict.kind !== 'role_conflict')
})
const roleConflicts = computed(() => mergePreview.value?.resolvableConflicts ?? [])
const applyItems = computed(() => mergePreview.value?.plan.filter((item) => item.outcome === 'apply') ?? [])
const skipItems = computed(() => mergePreview.value?.plan.filter((item) => item.outcome === 'skip') ?? [])

const allRoleConflictsDecided = computed(
  () => roleConflicts.value.every((item) => resolutions[item.decisionId] !== ''),
)
const mergeBlocked = computed(
  () =>
    !mergePreview.value ||
    mergePreview.value.packageConflicts.length > 0 ||
    hardConflicts.value.length > 0 ||
    !allRoleConflictsDecided.value,
)

const closeMerge = (): void => {
  mergeVisible.value = false
  mergePreview.value = null
}

const confirmMerge = (): void => {
  if (!mergePreview.value) return
  const payload: MergeResolution[] = Object.entries(resolutions)
    .filter(([, choice]) => choice !== '')
    .map(([decisionId, resolution]) => ({
      decisionId,
      resolution: resolution as 'keep_local' | 'use_incoming',
    }))
  const result = store.mergeCountersignPackage(mergePreview.value, payload)
  if (!result.ok) {
    toast.add({
      severity: 'error',
      summary: '合并失败，整包已回滚',
      detail: '仍有未解决冲突，原会签、版本基线与审计轨迹保持原样。',
      life: 5000,
    })
    return
  }
  closeMerge()
  toast.add({
    severity: 'success',
    summary: '会签包合并完成',
    detail: `并入 ${result.report.applied} 条，重复跳过 ${result.report.skipped} 条`,
    life: 3500,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`当前版本 ${latestVersion?.label ?? '未建立'} 仅展示受变更影响、需要重新审核的威胁。`"
    >
      <template #actions>
        <Button label="导出会签包" icon="pi pi-box" outlined @click="exportPackage" />
        <Button label="接收回传包" icon="pi pi-inbox" @click="triggerImport" />
        <input
          ref="fileInput"
          type="file"
          accept="application/json,.json"
          style="display: none"
          @change="void onPackageFile($event)"
        />
      </template>
    </PageHeader>

    <section v-if="store.lastMergeReport" class="merge-banner">
      <div class="merge-banner-head">
        <strong><i class="pi pi-check-circle"></i> 最近一次离线会签包合并结果</strong>
        <span>{{ new Date(store.lastMergeReport.mergedAt).toLocaleString('zh-CN') }} · 来源 {{ store.lastMergeReport.source }}</span>
      </div>
      <div class="merge-banner-stats">
        <span>包基线 v1.{{ store.lastMergeReport.baseRevision }}</span>
        <span class="ok">并入 {{ store.lastMergeReport.applied }} 条</span>
        <span class="muted">重复跳过 {{ store.lastMergeReport.skipped }} 条</span>
        <span class="muted">冲突 {{ store.lastMergeReport.conflicts }} 条</span>
      </div>
      <ul v-if="store.lastMergeReport.appliedItems.length" class="merge-banner-list">
        <li v-for="item in store.lastMergeReport.appliedItems" :key="item.decisionId">
          <StatusTag :value="item.decision" kind="review" />
          <span>{{ threatLabel(item.threatId) }} · {{ roleLabel(item.role) }} · {{ item.actor }}</span>
          <p>{{ item.comment }}</p>
        </li>
      </ul>
    </section>

    <section class="version-context">
      <div>
        <span>审核基线</span>
        <strong>{{ latestVersion?.label ?? '尚未建立版本' }}</strong>
      </div>
      <div>
        <span>受影响威胁</span>
        <strong>{{ affectedThreats.length }} 条</strong>
      </div>
      <div>
        <span>创建时间</span>
        <strong>
          {{ latestVersion ? new Date(latestVersion.createdAt).toLocaleString('zh-CN') : '-' }}
        </strong>
      </div>
    </section>

    <div class="review-board">
      <section class="review-list">
        <article
          v-for="threat in affectedThreats"
          :key="threat.id"
          class="review-card"
          :class="{ selected: selectedThreatId === threat.id }"
          @click="selectedThreatId = threat.id"
        >
          <div class="review-card-head">
            <div>
              <span class="mono">{{ threat.code }}</span>
              <h2>{{ threat.title }}</h2>
            </div>
            <StatusTag :value="threat.reviewStatus" kind="review" />
          </div>
          <div class="role-grid">
            <div v-for="role in roleOptions" :key="role.value" class="role-state">
              <span>{{ role.label }}</span>
              <strong :class="{ pending: statusForRole(threat, role.value) === 'pending' }">
                {{ decisionLabel(statusForRole(threat, role.value)) }}
              </strong>
            </div>
          </div>
          <ProgressBar
            :value="reviewProgress(decisionsForThreat(store.data.decisions, threat.id, threat.revision))"
            :show-value="false"
            class="review-progress"
          />
        </article>
      </section>

      <aside class="decision-panel">
        <template v-if="selectedThreat">
          <div class="decision-head">
            <div>
              <span class="mono">{{ selectedThreat.code }}</span>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
          </div>
          <p class="decision-description">{{ selectedThreat.description }}</p>
          <Button label="提交会签意见" icon="pi pi-pencil" @click="openDecision" />

          <section class="decision-history">
            <h3>当前版本会签记录</h3>
            <article v-for="decision in currentDecisions" :key="decision.id" class="decision-entry">
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
              </div>
              <StatusTag :value="decision.decision" kind="review" />
              <p>{{ decision.comment }}</p>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
            <div v-if="currentDecisions.length === 0" class="empty-state">尚未提交会签意见。</div>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条受影响威胁。</div>
      </aside>
    </div>

    <Dialog v-model:visible="decisionVisible" header="提交会签意见" modal :style="{ width: '620px' }">
      <div class="editor-form">
        <div class="field">
          <label>会签角色</label>
          <Select
            v-model="form.role"
            :options="roleOptions"
            option-label="label"
            option-value="value"
            @change="changeRole"
          />
        </div>
        <div class="field">
          <label>会签人</label>
          <InputText v-model="form.actor" />
        </div>
        <div class="field field-wide">
          <label>意见类型</label>
          <Select
            v-model="form.decision"
            :options="decisionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>意见与条件</label>
          <Textarea
            v-model="form.comment"
            rows="5"
            placeholder="通过、降级、接受或补证都需要写明具体条件"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="decisionVisible = false" />
        <Button label="提交意见" icon="pi pi-check" @click="submitDecision" />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="mergeVisible"
      header="接收离线会签包 — 合并预检"
      modal
      :style="{ width: '860px' }"
      @hide="closeMerge"
    >
      <template v-if="mergePreview">
        <section class="merge-meta">
          <div>
            <span>包基线</span>
            <strong>v1.{{ mergePreview.pkg.baseRevision }}</strong>
          </div>
          <div>
            <span>当前基线</span>
            <strong>v1.{{ store.data.currentRevision }}</strong>
          </div>
          <div>
            <span>导出时间</span>
            <strong>{{ new Date(mergePreview.pkg.exportedAt).toLocaleString('zh-CN') }}</strong>
          </div>
          <div>
            <span>导出人</span>
            <strong>{{ mergePreview.pkg.exportedBy }}</strong>
          </div>
        </section>

        <section v-if="mergePreview.packageConflicts.length" class="conflict-section">
            <h3><i class="pi pi-ban"></i> 包级冲突（必须回滚，不可继续）</h3>
            <article v-for="(conflict, index) in mergePreview.packageConflicts" :key="`pkg-${index}`" class="conflict-item hard">
              <strong>{{ conflict.title }}</strong>
              <p>{{ conflict.detail }}</p>
            </article>
          </section>

        <section v-if="hardConflicts.length" class="conflict-section">
          <h3><i class="pi pi-exclamation-triangle"></i> 逐条冲突（{{ hardConflicts.length }}）</h3>
          <article
            v-for="conflict in hardConflicts"
            :key="`${conflict.kind}-${conflict.threatId ?? ''}-${conflict.role ?? ''}`"
            class="conflict-item hard"
          >
            <span class="conflict-kind">{{ conflictKindLabel(conflict.kind) }}</span>
            <strong>{{ conflict.title }}</strong>
            <p>{{ conflict.detail }}</p>
          </article>
        </section>

        <section v-if="roleConflicts.length" class="conflict-section">
          <h3><i class="pi pi-question-circle"></i> 同一角色重复意见 — 重新确认通过或驳回</h3>
          <article v-for="item in roleConflicts" :key="item.decisionId" class="conflict-item">
            <div class="conflict-text">
              <strong>{{ threatLabel(item.threatId) }} · {{ roleLabel(item.role) }}</strong>
              <p>{{ item.conflict?.detail }}</p>
            </div>
            <Select
              v-model="resolutions[item.decisionId]"
              :options="resolutionOptions"
              option-label="label"
              option-value="value"
              placeholder="请重新确认"
              class="resolution-select"
            />
          </article>
        </section>

        <section v-if="applyItems.length" class="merge-section">
          <h3>将补入的缺失角色意见（{{ applyItems.length }}）</h3>
          <ul>
            <li v-for="item in applyItems" :key="item.decisionId">
              <StatusTag :value="item.decision" kind="review" />
              <span>{{ threatLabel(item.threatId) }} · {{ roleLabel(item.role) }} · {{ item.actor }}</span>
            </li>
          </ul>
        </section>

        <section v-if="skipItems.length" class="merge-section muted-section">
          <h3>重复意见，仅保留一条（{{ skipItems.length }}）</h3>
          <ul>
            <li v-for="item in skipItems" :key="item.decisionId">
              <span>{{ threatLabel(item.threatId) }} · {{ roleLabel(item.role) }} · {{ item.note }}</span>
            </li>
          </ul>
        </section>

        <p v-if="mergeBlocked" class="rollback-note">
          <i class="pi pi-info-circle"></i>
          存在未解决冲突时点击合并将整包回滚：原会签、版本基线与审计轨迹保持原样。
        </p>
      </template>

      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="closeMerge" />
        <Button
          label="确认合并"
          icon="pi pi-check"
          :disabled="mergeBlocked"
          @click="confirmMerge"
        />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.version-context {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.version-context > div {
  display: grid;
  gap: 7px;
  padding: 14px 16px;
  background: #fff;
}

.version-context span {
  color: #717c8f;
  font-size: 11px;
}

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(390px, 0.75fr);
  gap: 16px;
  align-items: start;
}

.review-list {
  display: grid;
  gap: 12px;
}

.review-card {
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  cursor: pointer;
}

.review-card:hover,
.review-card.selected {
  border-color: #7898bb;
  box-shadow: 0 0 0 1px rgba(70, 108, 150, 0.1);
}

.review-card-head,
.decision-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
}

.review-card h2,
.decision-head h2 {
  margin: 6px 0 0;
  font-size: 16px;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-top: 16px;
}

.role-state {
  display: grid;
  gap: 4px;
  padding: 9px 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
  background: #f9fafb;
}

.role-state span {
  color: #737e91;
  font-size: 10px;
}

.role-state strong {
  color: #2e684f;
  font-size: 11px;
}

.role-state strong.pending {
  color: #a05a00;
}

.review-progress {
  height: 4px;
  margin-top: 14px;
}

.decision-panel {
  position: sticky;
  top: 82px;
  padding: 18px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
}

.decision-description {
  margin: 14px 0 18px;
  color: #59657a;
  font-size: 13px;
  line-height: 1.65;
}

.decision-history {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #e5e9ef;
}

.decision-history h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.decision-entry {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  padding: 11px 0;
  border-bottom: 1px solid #eef0f3;
}

.decision-entry > div {
  display: grid;
  gap: 3px;
}

.decision-entry span,
.decision-entry time {
  color: #7a8496;
  font-size: 10px;
}

.decision-entry p {
  grid-column: 1 / -1;
  margin: 0;
  color: #566176;
  font-size: 12px;
  line-height: 1.5;
}

.merge-banner {
  margin: 16px 0;
  padding: 14px 16px;
  border: 1px solid #bfe0d0;
  border-left: 4px solid #2f8f69;
  border-radius: 7px;
  background: #f3faf6;
}

.merge-banner-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
}

.merge-banner-head i {
  color: #2f8f69;
}

.merge-banner-head span,
.merge-banner-stats {
  color: #697588;
  font-size: 11px;
}

.merge-banner-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  margin: 8px 0 4px;
}

.merge-banner-stats .ok {
  color: #2f8f69;
  font-weight: 700;
}

.merge-banner-stats .muted {
  color: #8a94a4;
}

.merge-banner-list {
  display: grid;
  gap: 6px;
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
}

.merge-banner-list li {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.merge-banner-list li p {
  flex-basis: 100%;
  margin: 0;
  color: #5d6879;
  font-size: 11px;
}

.merge-meta {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1px;
  margin-bottom: 16px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.merge-meta div {
  display: grid;
  gap: 5px;
  padding: 10px 12px;
  background: #fff;
}

.merge-meta span {
  color: #7a8498;
  font-size: 10px;
}

.merge-meta strong {
  font-size: 12px;
}

.conflict-section,
.merge-section {
  margin-bottom: 16px;
}

.conflict-section h3,
.merge-section h3 {
  margin: 0 0 8px;
  font-size: 13px;
}

.conflict-item {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
  margin-bottom: 8px;
  padding: 11px 12px;
  border: 1px solid #e0c3bf;
  border-left: 3px solid #c64b39;
  border-radius: 6px;
  background: #fdf7f6;
}

.conflict-item strong {
  font-size: 12px;
}

.conflict-kind {
  padding: 2px 8px;
  border-radius: 4px;
  color: #a83c2c;
  background: #f6ded9;
  font-size: 10px;
  font-weight: 700;
}

.conflict-item p {
  flex-basis: 100%;
  margin: 2px 0 0;
  color: #5f6a7e;
  font-size: 11px;
  line-height: 1.55;
}

.conflict-text {
  flex: 1 1 320px;
  display: grid;
  gap: 3px;
}

.resolution-select {
  min-width: 240px;
}

.merge-section ul {
  display: grid;
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.merge-section li {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: #4d596d;
}

.muted-section {
  color: #8893a3;
}

.rollback-note {
  margin: 4px 0 0;
  padding: 9px 12px;
  border-radius: 5px;
  color: #8a4a2a;
  background: #fdf2ea;
  font-size: 11px;
}
</style>
