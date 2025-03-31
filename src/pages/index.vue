<template>
  <main id="main">
    <!-- Hero Section -->
    <section id="hero" class="hero">
      <div class="container-fluid px-0">
        <div class="row g-0">
          <div class="col-md-5 hero-left d-flex align-items-center">
            <div class="hero-left-content">
              <img id="mapex_explorer_logo" src="/img/mappings_explorer_logo_h214.png" alt="Mappings Explorer" />
              <blockquote data-aos="fade-up" data-aos-delay="100">
                <p>
                  Mappings Explorer enables cyber defenders to understand how security controls and capabilities map onto the adversary behaviors catalogued in the
                  <a href="https://attack.mitre.org/" target="_blank" class="white-link">MITRE ATT&CK®</a> knowledge base. These mappings form a bridge between the threat-informed approach to cybersecurity and the traditional security controls perspective. 
                </p>
              </blockquote>
              <NuxtLink to="/about/" class="btn-get-started mt-3" data-aos="fade-up" data-aos-delay="200">
                Learn More
              </NuxtLink>
            </div>
          </div>
          <div class="col-md-7 hero-right"></div>
        </div>
      </div>
    </section>

    <!-- Call To Action -->
    <CallToAction
      type="search"
      title="Search All Mappings"
      message="Search by any ATT&CK object or security capability to get the associated mappings."
    />

    <FrameworksGraphic />


  </main>
</template>

<script setup>
import FrameworksGraphic from '~/components/FrameworksGraphic.vue'
import CallToAction from '~/components/CallToAction.vue'
import { ref, onMounted } from 'vue'

const urlPrefix = ref('/')
const frameworks = ref([])

onMounted(async () => {
  try {
    const resp = await fetch('/frameworks.json')
    frameworks.value = await resp.json()
  } catch (e) {
    console.error('Failed to load frameworks.json', e)
  }
})

</script>


<style scoped>

.mapping-frameworks {
  padding: 60px 20px;
  background: #fff;
}

.mapping-frameworks .section-header {
  text-align: center;
  padding-bottom: 30px;
}

.frameworks-grid {
  display: grid; 
  grid-template-columns: repeat(3, minmax(280px, 1fr));
  gap: 30px;
  justify-content: center; 
  max-width: 1200px;      
  margin: 0 auto;          
}


@media (max-width: 992px) {
  .frameworks-grid {
    grid-template-columns: repeat(2, minmax(280px, 1fr));
  }
}

@media (max-width: 576px) {
  .frameworks-grid {
    grid-template-columns: 1fr;
  }
}

/* Card styling for each framework item */
.framework-card {
  background: #fafafa;
  border: none;             
  display: flex;
  flex-direction: column;
}

.framework-card h3 {
  font-weight: 1.1rem;          
  text-align: left;
}

.framework-desc {
  font-size: 1rem;
  line-height: 1.5;
  text-align: left;
}

.framework-card p,
.framework-info {
  text-align: left;
}

.framework-info {
  font-size: 0.9rem;
  color: #333;
  text-align: left;
}

/* Learn More button/link */
.btn-learn-more {
  display: inline-block;
  background: var(--color-default, #212c5e);
  color: #fff;
  padding: 10px 20px;
  border-radius: 4px;
  text-decoration: none;
  font-size: 0.85rem;
  transition: 0.3s;
}

.btn-learn-more:hover {
  background: var(--color-primary, #c2eaf6);
  color: #212c5e;
}
.hero {
  min-height: calc(100vh - 130px);
  display: flex;
  flex-wrap: wrap;
  margin: 0;
  padding: 0;
  width: 100%;
  background: url("../public/img/background.jpeg") center/cover no-repeat;
}

.hero-left {
  background-color: var(--color-default);
  padding: 60px 20px;
  flex: 0 0 40%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
}


.hero-left-content {
  max-width: 400px;
  margin: 0 auto;
}

#mapex_explorer_logo {
  height: 80px;
  width: auto;
  margin-bottom: 20px;
}

.hero-left-content blockquote {
  color: #fff;
  padding-left: 20px;
  font-size: 15px;
  border-left: 3px solid var(--color-primary);
  margin: 25px 0;
  line-height: 1.4;
}

/* Right (Background Image) */
.hero-right {
  flex: 1;
  min-height: calc(100vh - 100px);
  background-color: rgba(30, 40, 69, 0.4); /* adjust alpha to taste */

}

.btn-get-started {
  font-family: var(--font-primary);
  font-weight: 500;
  font-size: 15px;
  letter-spacing: 1px;
  padding: 12px 30px;
  border-radius: 50px;
  transition: 0.5s;
  color: var(--color-default);
  background: var(--color-primary);
  text-decoration: none;
}

.btn-get-started:hover {
  background: #b3e2f0;
}

.input-group {
  display: flex;
  max-width: 500px;
  margin: 20px auto 0;
}

.input-group input {
  flex: 1;
  padding: 10px;
  font-size: 1rem;
  border: 1px solid #ccc;
  border-right: none;
  border-radius: 4px 0 0 4px;
}

.input-group-text {
  background: var(--color-primary);
  padding: 10px;
  border-radius: 0 4px 4px 0;
}

.input-group-text a {
  color: #fff;
  display: inline-block;
}

</style>