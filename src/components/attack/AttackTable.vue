<template>
  <table class="w-full border-collapse">
    <thead>
      <tr>
        <th v-for="header in headers" :key="header" class="border px-4 py-2">{{ header }}</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="row in rows.slice(0, maxCount)" :key="row.id">
        <td v-for="header in headers" :key="header" class="border px-4 py-2">
          <span v-if="row[header]">{{ row[header] }}</span>
        </td>
      </tr>
    </tbody>
  </table>

  <div v-if="rows.length > maxCount" class="mt-4 text-right">
    <a :href="fullLink" target="_blank">
      View all {{ fullSize }} entries →
    </a>
  </div>
</template>

<script setup>
const props = defineProps({
  headers: Array,
  rows: Array,
  urlPrefix: String,
  maxCount: Number,
  fullLink: String,
  fullSize: String,
})
</script>
