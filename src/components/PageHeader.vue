<script setup lang="ts">
defineProps<{
  title: string
  description: string
  eyebrow?: string
}>()
</script>

<template>
  <header class="page-header">
    <div>
      <div v-if="eyebrow" class="eyebrow">{{ eyebrow }}</div>
      <h1 class="page-title">{{ title }}</h1>
      <p class="page-description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="page-actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 18px;
}

.page-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 2px;
  white-space: nowrap;
}

.eyebrow {
  margin-bottom: 7px;
  color: #3767a5;
  font-size: 12px;
  font-weight: 700;
}
</style>
