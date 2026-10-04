<script setup lang="ts">
import Message from 'primevue/message'
import StatusTag from '@/components/StatusTag.vue'
import type { MergeResult } from '@/models/domain'
import { CONFLICT_LABELS, DECISION_LABELS, ROLE_LABELS } from '@/services/countersignPackage'

defineProps<{
  result: MergeResult
}>()

const actionLabels: Record<string, string> = {
  added: '补齐',
  replaced: '重新确认',
  skipped: '跳过保留',
}
</script>

<template>
  <section class="merge-report">
    <div class="merge-report-head">
      <div>
        <h3>
          {{ result.ok ? '合并完成' : '合并失败 · 整包回滚' }}
        </h3>
        <span class="muted">
          校验时间 {{ new Date(result.attemptedAt).toLocaleString('zh-CN') }}
          <template v-if="result.source">
            ｜回传包基线 v1.{{ result.source.modelRevision }}
            <span v-if="result.source.supplementOnly" class="supplement-flag">旧包仅补缺</span>
            ｜{{ result.source.versionLabel }}
          </template>
        </span>
      </div>
      <StatusTag :value="result.ok ? 'approved' : 'rejected'" kind="review" />
    </div>

    <Message
      v-if="!result.ok"
      severity="error"
      :closable="false"
      class="merge-banner"
    >
      发现 {{ result.conflicts.length }} 项冲突，未写入任何意见；原会签、版本基线与审计轨迹保持原样，请逐条处理后重新回传。
    </Message>
    <Message
      v-else
      severity="success"
      :closable="false"
      class="merge-banner"
    >
      新增 {{ result.appliedCount }} 条、重新确认替换 {{ result.replacedCount }} 条、跳过保留
      {{ result.skippedCount }} 条；受影响 {{ result.affectedThreatIds.length }} 条威胁的会签状态已重新计算，报告与版本页同步更新。
    </Message>

    <div v-if="result.conflicts.length" class="merge-section">
      <h4>冲突清单（{{ result.conflicts.length }}）</h4>
      <ul class="conflict-list">
        <li v-for="(conflict, index) in result.conflicts" :key="`${conflict.kind}-${index}`">
          <span class="conflict-kind">{{ CONFLICT_LABELS[conflict.kind] }}</span>
          <span>{{ conflict.message }}</span>
        </li>
      </ul>
    </div>

    <div v-if="result.entries.length" class="merge-section">
      <h4>意见处理明细（{{ result.entries.length }}）</h4>
      <ul class="entry-list">
        <li v-for="(entry, index) in result.entries" :key="`${entry.decision.id}-${index}`">
          <div class="entry-head">
            <span class="mono">{{ entry.threatCode }}</span>
            <span>{{ ROLE_LABELS[entry.decision.role] }} · {{ entry.decision.actor }}</span>
            <span class="entry-action" :class="`action-${entry.action}`">
              {{ actionLabels[entry.action] }} · {{ DECISION_LABELS[entry.decision.decision] }}
            </span>
          </div>
          <p>{{ entry.decision.comment }}</p>
          <small class="muted">{{ entry.note }}</small>
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.merge-report {
  display: grid;
  gap: 12px;
}

.merge-report-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.merge-report-head h3 {
  margin: 0 0 5px;
  font-size: 14px;
}

.merge-report-head .muted {
  font-size: 11px;
}

.supplement-flag {
  margin-left: 6px;
  padding: 1px 6px;
  border-radius: 4px;
  color: #8a5a00;
  background: #fdf0d8;
  font-size: 10px;
}

.merge-banner {
  font-size: 12px;
}

.merge-section h4 {
  margin: 0 0 8px;
  font-size: 12px;
}

.conflict-list,
.entry-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.conflict-list li {
  display: grid;
  grid-template-columns: 92px minmax(0, 1fr);
  gap: 10px;
  padding: 9px 11px;
  border: 1px solid #f0d2cc;
  border-radius: 5px;
  background: #fdf4f2;
  font-size: 12px;
  line-height: 1.5;
}

.conflict-kind {
  color: #b23a28;
  font-weight: 700;
  font-size: 11px;
}

.entry-list li {
  display: grid;
  gap: 4px;
  padding: 10px 12px;
  border: 1px solid #e3e8ef;
  border-radius: 5px;
  background: #fafbfc;
}

.entry-head {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12px;
}

.entry-action {
  margin-left: auto;
  font-size: 11px;
  font-weight: 700;
}

.action-added {
  color: #2f7d58;
}

.action-replaced {
  color: #9a6410;
}

.action-skipped {
  color: #72809a;
}

.entry-list p {
  margin: 0;
  color: #4d586d;
  font-size: 12px;
  line-height: 1.5;
}

.entry-list small {
  font-size: 10px;
}
</style>
