<template>
    <main id="main">
      <!-- About Header -->
      <section id="about-header" class="header-container gray-bg text-left">
        <div class="container">
          <div class="row justify-content-center">
            <div class="col-lg-8">
              <h1 class="text-center mb-3">OVERVIEW</h1>
              <p>
                Mappings Explorer enables cyber defenders to understand how security
                controls and capabilities map onto the adversary behaviors catalogued in the
                <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK®</a>
                knowledge base. The
                <a href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/" target="_blank">
                  Center for Threat‑Informed Defense
                </a>
                created these open source mappings to serve as a bridge between the threat‑informed approach and traditional security controls.
              </p>
              <p>
                Mappings Explorer presents threat and mitigation data in accessible, customizable ways —
                empowering defenders worldwide to make threat‑informed decisions based on real‑world adversary behavior.
              </p>
            </div>
          </div>
        </div>
      </section>

    <!-- What is Mappings Explorer for? -->
    <section class="purpose-section">
      <ListGraphic
        title="What is Mappings Explorer for?"
        subtitle="You can use Mappings Explorer for many different purposes. Examples of usage include:"
        :items-per-row="2"
        :elements="[
          {
            title: 'Align Cyber Defense to Threats',
            description: 'Explore how security controls and capabilities can be used to protect from, detect, or respond to specific adversary behaviors.',
          },
          {
            title: 'Assess Unpatched Vulnerabilities',
            description: 'Understand how adversaries might exploit unpatched vulnerabilities and what adversaries may achieve by exploiting the vulnerability.',
          },
          {
            title: 'Evolve and Expand Cyber Defense',
            description: 'Visualize and assess deficiencies in cyber defense to plan future policy and security controls around real-world adversary behavior.',
          },
          {
            title: 'Effectively Describe Incidents',
            description: 'Create detailed incident reports incorporating ATT&CK-based threat intel, recommendations for increased security protocols, and response measures.',
          }
        ]"
      />
    </section>
  
      <!-- Get Involved CTA -->
      <CallToAction
        type="email"
        title="Get Involved"
        message='Are you using the <a href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/" target="_blank">Center for Threat‑Informed Defense’s</a> mappings? Questions or feedback? Get in touch!'
        buttonText="Email Us"
        href="mailto:ctid@mitre-engenuity.org?subject=Mappings%20Explorer"
        />
    </main>
  </template>
  
  <script setup>
import CallToAction from '@/components/CallToAction.vue';
import ListGraphic from '@/components/ListGraphic.vue';
  </script>
  
  <style scoped>
  .header-container { padding: 60px 0; }
  .header-container h1 { font-size: 2.5rem; font-weight:700; }
  .services-list .title { font-size:1.25rem; font-weight:600; margin-bottom:10px; }
  .call-to-action.gray-bg { background:#eff1f4; }
  .call-to-action h3 { font-size:28px; font-weight:700; }

  .purpose-section {
  max-width: 900px;
  margin: 0 auto;
  padding: 60px 20px;
}
  </style>
  