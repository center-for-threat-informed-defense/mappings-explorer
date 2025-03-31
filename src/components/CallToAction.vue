<template>
    <section id="call-to-action" class="call-to-action gray-bg">
      <div class="container" data-aos="fade-up">
        <div class="row justify-content-center">
          <!-- Email Section -->
          <div class="col-lg-6 text-center" v-if="type === 'email'">
            <h3>{{ title }}</h3>
            <h4 v-if="subtitle">{{ subtitle }}</h4>
            <p v-html="message"></p>
            <a
              class="cta-btn px-4 py-2 mt-2"
              :href="href"
            >
              {{ buttonText }}
            </a>
          </div>
  
          <!-- Search Section -->
          <div class="col-lg-8" v-else-if="type === 'search'">
            <div class="search-container text-center">
              <h3>{{ title }}</h3>
              <h4 v-if="subtitle">{{ subtitle }}</h4>
              <p>{{ message }}</p>
              <div class="input-group mb-3">
                <input
                  type="search"
                  id="landing-search-input"
                  class="form-control"
                  :placeholder="searchPlaceholder"
                />
                <button class="btn btn-outline-secondary" type="button" @click="performSearch">
                  <i class="bi bi-search"></i>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  </template>
  
  <script setup>
  import { ref } from 'vue';
  
  const props = defineProps({
    type: String, 
    title: String,
    subtitle: {
      type: String,
      default: '', 
    },
    message: String,
    buttonText: String,
    href: String,
    searchPlaceholder: {
      type: String,
      default: 'Search',
    },
  });
  
  
  function performSearch() {
  }
  
  </script>
  
  <style scoped>
  .call-to-action {
    background: #f4f4f4;
    padding: 100px 0;
  }
  .call-to-action h3 {
    font-size: 28px;
    font-weight: 700;
    text-transform: uppercase;
    margin-bottom: 25px;
    color: var(--color-text);
  }
  .call-to-action h4 {
    font-size: 22px;
    font-weight: 600;
    margin-bottom: 20px;
    color: var(--color-text-secondary);
  }
  .call-to-action p {
    color: var(--color-text);
    margin-bottom: 25px;
  }

.cta-btn {
  font-family: var(--font-default);
  font-weight: 500;
  font-size: 16px;
  letter-spacing: 1px;
  display: inline-block;
  padding: 12px 40px;
  border-radius: 50px;
  transition: 0.5s;
  margin: 10px;
  color: #fff;
  background: #2aa5df;
}

.cta-btn:hover {
  background: var(--color-primary);
}


  .input-group {
    max-width: 500px;
    margin: 20px auto 0;
  }
  </style>
  