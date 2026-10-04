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
import MergeReport from '@/components/MergeReport.vue'
import type {
  ActorRole,
  CountersignPackage,
  DecisionType,
  Threat,
} from '@/models/domain'
import {
  parseCountersignPackage,
  planMerge,
} from '@/services/countersignPackage'
import { decisionsForThreat, reviewProgress } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref('')
const decisionVisible = ref(false)

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

// ---------- 会签包导出 / 回传合并 ----------
const importVisible = ref(false)
const packageText = ref('')
const previewResult = ref<ReturnType<typeof planMerge> | null>(null)
const previewParsed = ref<CountersignPackage | null>(null)
const fileInput = ref<HTMLInputElement | null>(null)

const downloadPackage = (): void => {
  const pkg = store.exportCountersignPackage()
  const blob = new Blob([JSON.stringify(pkg, null, 2)], {
    type: 'application/json;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `会签包-r${pkg.modelRevision}-${pkg.exportedAt.slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
  toast.add({
    severity: 'success',
    summary: '会签包已导出',
    detail: `基线 r${pkg.modelRevision}，含 ${pkg.threats.length} 条威胁与 ${pkg.decisions.length} 条意见`,
    life: 3000,
  })
}

const openImport = (): void => {
  packageText.value = ''
  previewResult.value = null
  previewParsed.value = null
  importVisible.value = true
}

const onFileChosen = async (event: Event): Promise<void> => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  packageText.value = await file.text()
  input.value = ''
  checkPackage()
}

const checkPackage = (): void => {
  const parsed = parseCountersignPackage(packageText.value)
  if (parsed.error || !parsed.package) {
    previewParsed.value = null
    previewResult.value = {
      ok: false,
      attemptedAt: new Date().toISOString(),
      source: null,
      conflicts: [{ kind: 'invalid_package', message: parsed.error ?? '无法解析会签包。' }],
      entries: [],
      appliedCount: 0,
      replacedCount: 0,
      skippedCount: 0,
      affectedThreatIds: [],
    }
    return
  }
  previewParsed.value = parsed.package
  previewResult.value = planMerge(store.data, parsed.package)
}

const confirmMerge = (): void => {
  const result = store.applyCountersignImport(packageText.value)
  importVisible.value = false
  if (result.ok) {
    toast.add({
      severity: 'success',
      summary: '会签包已合并',
      detail: `新增 ${result.appliedCount} · 替换 ${result.replacedCount} · 跳过 ${result.skippedCount}`,
      life: 3500,
    })
  } else {
    toast.add({
      severity: 'error',
      summary: '合并失败，已整包回滚',
      detail: `${result.conflicts.length} 项冲突，原会签与基线未改动`,
      life: 4000,
    })
  }
}

/** 构造一个离线负责人回传包样例（可在文本框继续编辑后校验）。 */
const loadSamplePackage = (): void => {
  const base = store.exportCountersignPackage()
  const thr01 = store.data.threats.find((item) => item.id === 'thr-01')
  const sample: CountersignPackage = {
    ...base,
    exportedAt: new Date().toISOString(),
    exportedBy: '异地会签负责人',
    decisions: [
      ...base.decisions.filter(
        // 同角色重复意见：保留回传包中的最新一条，进入“重新确认”
        (decision) => !(decision.threatId === 'thr-01' && decision.role === 'security'),
      ),
      {
        id: 'offline-dec-thr01-security',
        threatId: 'thr-01',
        role: 'security',
        actor: '王岚（离线）',
        decision: 'approved' as DecisionType,
        comment: '旁路告警证据已在离线环境核验，补充一周告警样本后通过。',
        createdAt: new Date(Date.now() + 3600_000).toISOString(),
        revision: thr01?.revision ?? base.modelRevision,
      },
      {
        id: 'offline-dec-thr01-dev',
        threatId: 'thr-01',
        role: 'development',
        actor: '赵恺（离线）',
        decision: 'approved' as DecisionType,
        comment: '公网暴露面收敛已完成灰度，开发侧确认通过。',
        createdAt: new Date(Date.now() + 7200_000).toISOString(),
        revision: thr01?.revision ?? base.modelRevision,
      },
      {
        id: 'offline-dec-stale-demo',
        threatId: 'thr-03',
        role: 'security',
        actor: '离线旧版意见',
        decision: 'evidence_required' as DecisionType,
        comment: '这是一条基于旧修订 r1 的意见，用于演示修订失效冲突。',
        createdAt: new Date(Date.now() + 1800_000).toISOString(),
        revision: (thr01?.revision ?? 2) - 1,
      },
    ],
  }
  packageText.value = JSON.stringify(sample, null, 2)
  checkPackage()
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`当前版本 ${latestVersion?.label ?? '未建立'} 仅展示受变更影响、需要重新审核的威胁。`"
    />

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

    <section class="package-hub panel">
      <div class="panel-header">
        <div>
          <h2 class="panel-title">离线会签包交换</h2>
          <p class="hub-subtitle">
            导出当前会签包分发给异地负责人；负责人离线审完回传后在此合并。包内带模型版本号与逐条威胁修订号，
            修订更新后旧意见失效；旧包只补缺失角色，不能覆盖新修订意见。
          </p>
        </div>
        <div class="hub-actions">
          <Button label="导出当前会签包" icon="pi pi-download" severity="secondary" outlined @click="downloadPackage" />
          <Button label="接收回传包并合并" icon="pi pi-upload" @click="openImport" />
        </div>
      </div>
      <div class="hub-rules">
        <span><i class="pi pi-check-circle"></i> 同一角色重复意见仅保留一条，并按回传意见重新确认通过/驳回</span>
        <span><i class="pi pi-times-circle"></i> 合并失败整包回滚，原会签、版本基线与审计轨迹不变，冲突逐条列出</span>
        <span><i class="pi pi-sync"></i> 合并后报告页、版本页与会签中心展示同一结果</span>
      </div>
      <MergeReport v-if="store.lastMergeResult" :result="store.lastMergeResult" class="hub-report" />
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

    <Dialog v-model:visible="importVisible" header="接收负责人回传会签包" modal :style="{ width: '860px' }">
      <div class="import-dialog-body">
        <div class="import-toolbar">
          <Button label="选择回传包文件" icon="pi pi-file" severity="secondary" outlined @click="fileInput?.click()" />
          <input
            ref="fileInput"
            type="file"
            accept="application/json,.json"
            hidden
            @change="onFileChosen"
          />
          <Button label="载入演示回传包" icon="pi pi-microchip" severity="secondary" text @click="loadSamplePackage" />
          <Button label="校验合并规则" icon="pi pi-search" outlined @click="checkPackage" :disabled="!packageText.trim()" />
          <span class="muted import-hint">也可将异地负责人回传的 JSON 直接粘贴到下方文本框</span>
        </div>
        <Textarea
          v-model="packageText"
          rows="10"
          class="package-editor"
          placeholder="在此粘贴回传会签包 JSON，或点击「选择回传包文件」"
        />

        <div v-if="previewResult" class="preview-report">
          <div v-if="previewParsed" class="preview-meta muted">
            回传包基线 v1.{{ previewParsed.modelRevision }}（{{ previewParsed.versionLabel }}）
            ｜导出时间 {{ new Date(previewParsed.exportedAt).toLocaleString('zh-CN') }}
            ｜意见 {{ previewParsed.decisions.length }} 条
            <span v-if="previewParsed.modelRevision < store.data.currentRevision" class="supplement-tag">
              旧包 · 仅补缺
            </span>
          </div>
          <MergeReport :result="previewResult" />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="importVisible = false" />
        <Button
          label="确认合并"
          icon="pi pi-check-circle"
          :disabled="!previewResult || !previewResult.ok"
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

.package-hub {
  display: grid;
  gap: 14px;
}

.hub-subtitle {
  margin: 6px 0 0;
  color: #6d788c;
  font-size: 12px;
  line-height: 1.6;
  max-width: 760px;
}

.hub-actions {
  display: flex;
  gap: 10px;
}

.hub-rules {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 22px;
  padding: 0 16px;
  color: #5d687c;
  font-size: 11px;
}

.hub-rules span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.hub-rules i.pi-check-circle {
  color: #2f8f69;
}

.hub-rules i.pi-times-circle {
  color: #c64b39;
}

.hub-rules i.pi-sync {
  color: #4c78a8;
}

.hub-report {
  margin: 0 16px 16px;
  padding: 14px;
  border: 1px solid #e2e7ee;
  border-radius: 6px;
  background: #fafbfd;
}

.import-dialog-body {
  display: grid;
  gap: 12px;
}

.import-toolbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.import-hint {
  font-size: 11px;
}

.package-editor {
  width: 100%;
  font-family: "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.preview-report {
  display: grid;
  gap: 10px;
  padding: 12px;
  border: 1px solid #e2e7ee;
  border-radius: 6px;
  background: #fafbfd;
}

.preview-meta {
  font-size: 11px;
}

.supplement-tag {
  margin-left: 8px;
  padding: 1px 7px;
  border-radius: 4px;
  color: #8a5a00;
  background: #fdf0d8;
}
</style>
