<template>
  <main id="main">
    <section id="header-container" class="header-container">
      <div class="container">
        <div class="row justify-content-center">
          <div class="col-lg-8 text-center">
            <h1>ABOUT <span class="highlight">MAPPINGS</span></h1>
            <p>
              The
              <a href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/" target="_blank">
                Center for Threat-Informed Defense
              </a>
              security capability mappings to
              <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK®</a>
              empower defenders with data. Mappings Explorer provides a central location
              where all Center mapping resources are provided in an accessible and connected
              manner, improving a defender’s ability to make threat-informed decisions
              based on mapped security capabilities.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- Mapping Frameworks Section -->
    <FrameworksGraphic />
  </main>
</template>

<script setup>
import FrameworksGraphic from '~/components/FrameworksGraphic.vue'
</script>

<style scoped>
.header-container {
  padding: 60px 0;
}
.header-container h1 {
  font-size: 2.5rem;
  font-weight: 700;
}
.header-container p {
  margin-top: 1rem;
  font-size: 1rem;
  line-height: 1.6;
}
</style>
