<script setup>
import { useRoute } from 'vue-router'

const route = useRoute()

const { data: frameworks } = await useFetch('/api/frameworks')

// Lookup framework using the route param
const framework = computed(() =>
  frameworks.value?.find(f => f.id === route.params.id)
)

const selectedVersion = ref(framework.value?.versions?.[0] || null)
const attackVersion = ref(framework.value?.attackVersions?.[0] || null)
const domain = ref(framework.value?.attackDomains?.[0]?.toLowerCase() || 'enterprise')
const mappings = ref([])
const loading = ref(true)

const loadMappings = async () => {
  if (!selectedVersion.value || !attackVersion.value || !framework.value) return

  const projectId = framework.value.id
  const controlVersion = `${projectId}-${selectedVersion.value}`

  // const path = `/data/${projectId}/attack-${attackVersion.value}/${controlVersion}/${domain.value}/${controlVersion}_attack-${attackVersion.value}-${domain.value}.json`

  const { data } = await useFetch(`/api/loadMappings`, {
  params: {
    path: `data/${projectId}/attack-${attackVersion.value}/${controlVersion}/${domain.value}/${controlVersion}_attack-${attackVersion.value}-${domain.value}.json`
  }
})

mappings.value = data.value?.mapping_objects || []
}

// Load initial mappings (optional: only if framework exists)
if (framework.value) {
  await loadMappings()
}

</script>

<template>
  <div>

    <section v-if="framework" id="header-container" class="header-container white-bg">
      <div class="container">
        <div class="row align-items-start">
          <!-- Left -->
          <div class="col-lg-8">
            <h1 class="title">{{ framework.label }}</h1>
            <p>{{ framework.description }}</p>
            <p>
              <span>
                ATT&amp;CK Versions: <strong>{{ framework.attackVersions.join(', ') }}</strong>
                &nbsp;&nbsp;
              </span>
              <span>
                ATT&amp;CK Domain: <strong>{{ framework.attackDomains.join(', ') }}</strong>
              </span> 
          </p>
            <p v-if="framework.resources?.length" class="resource-links">
              <template v-for="(r,i) in framework.resources" :key="r.link">
                <a :href="r.external ? r.link : '/' + r.link" class="link" target="_blank">{{ r.label }}</a>
                <span v-if="i < framework.resources.length - 1"> | </span>
              </template>
            </p>
          </div>

          <!-- Right -->
          <div class="col-lg-4 p-5 download-artifacts">
            <h6>Download Mapping Artifacts:</h6>
            <div class="downloads">
              <p v-for="ext in ['json','yaml','csv','xlsx','stix.json','navigator_layer.json']" :key="ext">
                <a
                  class="link"
                  :href="`/external/${route.params.id}`"
                  download
                >
                <!-- TODO have this download the correct generated files i.e. something like :href="selectedVersion && attackVersion ? `/data/${framework.id}/attack-${attackVersion}/${selectedVersion}/${domain}/${selectedVersion}_attack-${attackVersion}-${domain}.${ext}` : '#'" -->
                  <i class="bi bi-download"></i>
                  {{ ext.toUpperCase().replace('_', ' ').replace('.JSON', '').replace('.LAYER', '') }}
                </a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section v-if="framework" class="version-select py-4">
      <div class="container">
        <h2>SELECT VERSIONS</h2>
        <div class="row">
          <div class="col-md-3">
            <label>{{ framework.label }} Version</label>
            <select v-model="selectedVersion" class="form-select">
              <option v-for="v in framework.versions" :key="v" :value="v">{{ v }}</option>
            </select>
          </div>
          <div class="col-md-3">
            <label>ATT&AMP;CK Version</label>
            <select v-model="attackVersion" class="form-select">
              <option v-for="v in framework.attackVersions" :key="v" :value="v">{{ v }}</option>
            </select>
          </div>
          <div class="col-md-3">
            <label>ATT&AMP;CK Domain</label>
            <select v-model="domain" class="form-select">
              <option v-for="d in framework.attackDomains" :key="d" :value="d.toLowerCase()">{{ d }}</option>
            </select>
          </div>
          <div class="col-md-3 d-flex align-items-end">
            <button class="btn btn-pill w-100" @click="loadMappings">See Mappings</button>
          </div>
        </div>
      </div>
    </section>

    <section v-if="framework && mappings?.length" class="mapping-table">
      <div class="container">
        <div class="row justify-content-left">
          <div class="col-12" data-aos="fade-up">
            <h2>ALL MAPPINGS</h2>
            <table class="table table-bordered">
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>ATT&AMP;CK Technique</th>
                  <th>Category</th>
                  <th>Value</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(mapping, i) in mappings" :key="i">
                  <td>{{ mapping.capability_description }}</td>
                  <td>
                    <strong>{{ mapping.attack_object_id }}</strong><br />
                    <small>{{ mapping.attack_object_name }}</small>
                  </td>
                  <td>{{ mapping.score_category }}</td>
                  <td>{{ mapping.score_value }}</td>
                  <td>{{ mapping.comments }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <div v-else-if="loading" class="text-center py-5">Loading framework…</div>
    <div v-else class="text-center py-5">Framework not found</div>
  </div>
</template>

<style scoped>
.title {
  font-size: 2.5rem;
  font-weight: 700;
  color: var(--color-secondary);
}
.resource-links .link {
  font-weight: normal;
  color: var(--color-link);
  text-decoration: none;
}
.resource-links .link:hover {
  color: var(--color-primary);
}
.download-artifacts .downloads p {
  margin: 0.5rem 0;
}
.downloads a {
  font-weight: normal;
  display: inline-flex;
  align-items: center;
  color: var(--color-link);
  text-decoration: none;
}
.downloads i {
  margin-right: 6px;
}
.link:hover {
  color: var(--color-primary);
}
.mapping-table table {
  width: 100%;
  margin-top: 2rem;
}
.mapping-table th, .mapping-table td {
  padding: 0.75rem;
  text-align: left;
  border: 1px solid #ddd;
}

.btn-pill {
  font-family: var(--font-default);
  font-weight: 500;
  font-size: 15px;
  letter-spacing: 1px;
  padding: 12px 30px;
  border-radius: 50px;
  transition: 0.5s;
  color: white;
  background: var(--color-secondary);
  width: max-content;
  margin-top: auto !important;
  text-transform: uppercase;
  border: none;
  display: flex;
  justify-content: center;
  align-items: center;
}
</style>
