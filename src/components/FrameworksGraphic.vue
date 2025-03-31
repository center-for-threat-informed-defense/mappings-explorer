<template>
    <ListGraphic
      title="MAPPING FRAMEWORKS"
      :itemsPerRow="3"
      :elements="frameworkElements"
    />
  </template>
  
  <script setup>
  import { ref, onMounted } from 'vue'
  import ListGraphic from '@/components/ListGraphic.vue'
  
  const frameworkElements = ref([])
  
  onMounted(async () => {
    try {
      const resp = await fetch('/frameworks.json')
      const frameworks = await resp.json()
  
      frameworkElements.value = frameworks.map(f => ({
        title: f.label,
        description: f.description,
        properties: {
          'ATT&CK Version(s)': f.attackVersions,
          'ATT&CK Domain(s)': f.attackDomains
        },
        href: `/external/${f.id}`,
        link: 'Learn More'
      }))
    } catch (err) {
      console.error('Error loading frameworks.json', err)
    }
  })
  </script>
  