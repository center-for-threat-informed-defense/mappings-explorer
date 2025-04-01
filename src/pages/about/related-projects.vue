<template>
  <div>
    <section class="header-container gray-bg">
      <div class="container aos-init aos-animate">
        <div class="row justify-content-center">
          <div class="col-lg-8">
            <h1 class="text-center">
              <span class="highlight">RELATED</span> PROJECTS
            </h1>
            <p>
              The
              <a
                href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/"
                target="_blank"
              >
                Center for Threat-Informed Defense
              </a>
              creates solutions that expand upon the
              <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK®</a>
              knowledge base to better understand cyber adversaries and their tradecraft in order to advance
              threat-informed defense. The following Center projects are most closely
              related to the security capability mappings projects presented in Mappings Explorer.
            </p>
          </div>
        </div>
      </div>
    </section>

    <section class="examples-section white-bg">
      <ListGraphic
        title="Related to Mappings Explorer"
        :elements="relatedProjects"
        :items-per-row="2"
      />
    </section>

    <CallToAction
      type="email"
      title="Learn More"
      message='Interested in what other types of work the <a href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/" target="_blank">Center for Threat-Informed Defense does?</a> Check out other projects that we have published.'
      buttonText="View Published Projects"
      href="https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/our-work/"
    />
  </div>
</template>

<script setup>
import ListGraphic from '@/components/ListGraphic.vue'
import CallToAction from '@/components/CallToAction.vue'

const relatedProjects = [
  {
    title: 'Mappings Editor',
    description:
      'The Center for Threat-Informed Defense creates the data you see on this site using a specialized tool developed called Mappings Editor. This tool is optimized for mapping security capabilities to MITRE ATT&CK. It includes powerful features for efficiency and accuracy. We released it as a public beta for anybody who wants to create their own mappings, whether to share mappings of publicly known security capabilities, or to privately document your organization\'s internal security controls.',
    link: 'Learn More About Mappings Editor',
    href: 'https://github.com/center-for-threat-informed-defense/mappings-editor/wiki'
  },
  {
    title: 'ATT&CK Sync',
    description:
      'The ATT&CK Sync project streamlines upgrades to new versions of MITRE ATT&CK® by providing tools and resources to migrate existing projects to current ATT&CK versions in a timely and efficient manner. ATT&CK Sync provides tools and a methodology that organizations can implement to stay up to date.',
    link: 'Learn More About ATT&CK Sync',
    href: 'https://github.com/center-for-threat-informed-defense/attack-sync/wiki'
  },
  {
    title: 'Sensor Mappings to ATT&CK',
    description:
      'The Sensor Mappings to ATT&CK project provides a collection of resources to assist security operations teams and leaders with understanding which tools, capabilities, and events provide visibility into adversary behaviors. It connects ATT&CK data sources to logs, sensors, and other capabilities.',
    link: 'Learn More About Sensor Mappings',
    href: 'https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/'
  },
  {
    title: 'ATT&CK Powered Suit',
    description:
      'ATT&CK Powered Suit is a free browser extension that puts the MITRE ATT&CK® knowledge base at your fingertips. It enables quick searches, snippets, exports to Navigator, and more without disrupting your workflow.',
    link: 'Learn More About ATT&CK Powered Suit',
    href: 'https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/attack-powered-suit/'
  }
]
</script>

<style scoped>
.header-container {
  padding-top: 120px;
  padding-bottom: 60px;
}

.examples-section {
  max-width: 900px;
  margin: 0 auto;
  padding: 60px 20px;
}
</style>
