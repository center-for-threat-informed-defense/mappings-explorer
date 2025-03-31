<template>
    <div class="mb-6 flex space-x-4">
      <label>
        Version:
        <select v-model="localVersion">
          <option v-for="v in versions" :key="v" :value="v">{{ v }}</option>
        </select>
      </label>
  
      <label>
        Domain:
        <select v-model="localDomain">
          <option v-for="d in domains" :key="d" :value="d">{{ d }}</option>
        </select>
      </label>
    </div>
  </template>
  
  <script setup>
  import { ref, watch } from 'vue'
  import { useRouter } from 'vue-router'
  
  const props = defineProps({
    version: String,
    domain: String,
  })
  
  const emit = defineEmits(['update'])
  
  const router = useRouter()
  
  const versions = ['10.1','10.0','9.3']  // replace with dynamic fetch 
  const domains = ['enterprise','mobile','ics']
  
  const localVersion = ref(props.version)
  const localDomain = ref(props.domain)
  
  watch([localVersion, localDomain], () => {
    router.replace({
      query: { 'attack-version': localVersion.value, domain: localDomain.value }
    })
  })
  </script>
  