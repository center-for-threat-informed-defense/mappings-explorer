<template>
    <div id="matrix-page">
      <section class="header-container">
        <div class="container">
          <h1><span class="highlight">ATT&CK</span> MATRIX</h1>
          <p>{{ description }}</p>
        </div>
      </section>
  
      <div class="container version-select my-4">
        <label>Version:
          <select v-model="selectedVersion">
            <option v-for="v in allVersions" :key="v" :value="v">{{ v }}</option>
          </select>
        </label>
        <label class="ml-4">Domain:
          <select v-model="selectedDomain">
            <option v-for="d in allDomains" :key="d" :value="d">{{ d }}</option>
          </select>
        </label>
      </div>
  
      <section class="mapping-table container">
        <h2>ATT&CK v{{ selectedVersion }} {{ selectedDomain.toUpperCase() }} Matrix</h2>
        <div class="matrix-table-container overflow-scroll">
          <div v-for="tactic in tactics" :key="tactic.id" class="tactic-column">
            <h3>{{ tactic.name }}</h3>
            <div v-for="tech in tactic.techniques" :key="tech.id">
              {{ tech.name }}
            </div>
          </div>
        </div>
      </section>
    </div>
  </template>
  
  <script setup>
  import { ref, watch, onMounted } from 'vue'
  import { useRoute, useRouter } from 'vue-router'
  
  const route = useRoute()
  
  const selectedVersion = ref(route.query['attack-version'] || '')
  const selectedDomain = ref(route.query.domain || '')
  const allVersions = ref([])
  const allDomains = ref([])
  const matrixOrder = ref({})
  const tactics = ref([])
  const description = ref('')
  
  </script>
  
  <style scoped>
  .header-container { background:#fafafa; padding:2rem 0 }
  .mapping-table { margin-top:1rem }
  .tactic-column { display:inline-block; vertical-align:top; width:150px; margin-right:1rem }
  .highlight { color:#4f46e5 }
  </style>
  