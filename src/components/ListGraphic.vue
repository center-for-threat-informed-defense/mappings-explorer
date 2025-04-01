<template>
    <section id="elements-section" class="mapping-elements">
      <div class="container">
        <div class="section-header">
          <h2>{{ title }}</h2>
          <p v-if="subtitle">{{ subtitle }}</p>
        </div>
        <div class="row" :class="`row-cols-1 row-cols-md-2 row-cols-lg-${itemsPerRow}`">
          <div
            v-for="(element, index) in elements"
            :key="index"
            class="col"
          >
            <div class="element-card d-flex flex-column h-100 p-4">
              <div class="d-flex align-items-center mb-2">
                <div v-if="element.icon" class="me-2 icon-wrapper">
                  <i :class="element.icon"></i>
                </div>
                <h3 class="fw-bold mb-0">
                  {{ element.title }} <span v-if="element.tag" class="highlight"> ({{ element.tag }}) </span>
                </h3>
              </div>
              <p v-if="element.subtitle" class="text-muted mb-2">{{ element.subtitle }}</p>
              <div class="d-flex mb-3">
                <div v-if="!element.icon" class="accent-bar"></div>
                <p class="element-desc flex-grow-1 mb-3">{{ element.description || element.title }}</p>
              </div>
              <div class="element-info mb-3 text-start">
                <div v-if="element.properties">
                  <div
                    v-for="(value, label) in element.properties"
                    :key="label"
                  >
                    <strong>{{ label }}:</strong> {{ Array.isArray(value) ? value.join(', ') : value }}
                  </div>
                </div>
                <p v-if="element.link" class="d-flex mt-3">
                  <NuxtLink :to="element.href" class="learn-more-link mt-auto">
                    {{ element.link || 'Learn More' }} <span class="arrow">→</span>
                  </NuxtLink>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  </template>
  
  <script setup>
  defineProps({
    title: String,
    subtitle: String,
    itemsPerRow: {
      type: Number,
      default: 3
    },
    elements: {
      type: Array,
      required: true
    }
  })
  </script>
  
  <style scoped>
  .element-card {
    padding: 20px;
    border-radius: 4px;
    text-align: center;
    border: none;
    display: flex;
    flex-direction: column;
  }
  
  .element-card h3 {
    font-size: 1.2rem;
    text-align: left;
    margin-top: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
  }
  
  .icon-wrapper i {
    font-size: 1.75rem;
  }
  
  .element-card p {
    flex-grow: 1;
    color: var(--color-text-secondary);
    font-size: 0.95rem;
    line-height: 1.5;
  }
  
  .accent-bar {
    width: 3px;
    background-color: var(--color-purple);
    margin-right: 12px;
    height: 100%;
    flex-shrink: 0;
  }
  
  .element-desc {
    font-size: 1rem;
    line-height: 1.5;
    text-align: left;
  }
  
  .element-info {
    font-size: 0.9rem;
    color: var(--color-text-secondary);
    text-align: left;
  }
  
  .learn-more-link {
    color: var(--color-link) !important;
    font-weight: 400 !important;
    text-align: left;
    display: inline-block;
  }
  
  .learn-more-link .arrow {
    font-weight: 400 !important;
  }
  
  .learn-more-link:hover {
    text-decoration: underline;
  }
  </style>