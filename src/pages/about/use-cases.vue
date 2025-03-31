<template>
  <section id="header-container" class="header-container">
    <div class="container aos-init aos-animate">
      <div class="row justify-content-center">
        <div class="col-lg-8 text-center">
          <h1>MAPPINGS <span class="highlight">USE CASES</span></h1>
          <p>
            Mappings Explorer is valuable to a broad range of cyber professionals,
            through customizable understanding of how security controls and capabilities
            map onto the adversary behaviors catalogued in the
            <a href="https://attack.mitre.org/" target="_blank">MITRE ATT&CK®</a> knowledge base.
            These users encompass many roles and responsibilities associated with
            organizational cyber defense, risk management, threat prevention and detection,
            and incident response. These roles and responsibilities include:.
          </p>
        </div>
      </div>
    </div>
  </section>

  <ListGraphic
    title="Use Cases"
    :items-per-row="3"
    :elements="[
      {
        title: 'Incident Responder',
        tag: 'IR',
        icon: 'bi bi-person-badge',
        description:
          'Responsible for response, management, and coordination, and remediation activities for cyber incidents such as malware infections, data theft, ransomware encryption, denial of service, and control systems intrusions.',
      },
      {
        title: 'Chief Information Security Officer',
        tag: 'CISO',
        icon: 'bi bi-person-badge-fill',
        description:
          'Responsible for carrying out information security policies, procedures, and controls, and providing primary interface between senior managers and information system owners.',
      },
      {
        title: 'Information System Security Officer',
        tag: 'ISSO',
        icon: 'bi bi-person-badge',
        description:
          'Responsibilities include ensuring the appropriate operational security posture is maintained for information systems or programs.',
      },
      {
        title: 'Security Operations Center Analyst',
        tag: 'SOC',
        icon: 'bi bi-person-badge-fill',
        description:
          'Responsibilities include monitoring an organization’s networks and systems to detect threats and investigating potential security incidents.',
      },
      {
        title: 'Security Engineer',
        tag: 'SE',
        icon: 'bi bi-person-badge',
        description:
          'Responsibilities include developing and implementing security controls and solutions to protect networks and systems from unauthorized access and attacks.',
      },
      {
        title: 'Vulnerability Researcher',
        tag: 'VR',
        icon: 'bi bi-person-badge-fill',
        description:
          'Responsibilities include identifying and studying security vulnerabilities in systems or software to identify weaknesses and improve security.',
      },
      {
        title: 'Cyber Threat Intel Analyst',
        tag: 'CTI',
        icon: 'bi bi-person-badge',
        description:
          'Responsibilities include collecting data and information from various sources across the threat landscape to identify, assess, and recommend countermeasures for cyber threats.',
      },
      {
        title: 'Enterprise Fleet Manager',
        tag: 'EFM',
        icon: 'bi bi-person-badge',
        description:
          'Responsible for the overall management of a company\'s computer fleet, including procuring, maintaining, and updating enterprise systems.',
      },
    ]"
  />
  <section id="use-cases">
      <div class="container col-lg-8 offset-lg-2" data-aos="fade-up">
        <div class="section-header">
          <h2>Usage</h2>
          <p style="margin-bottom: 1em;">
            The Mappings Explorer website enables the following essential abilities:
          </p>
          <ol style="text-align: left; list-style: none; counter-reset: list-counter;">
            <li v-for="(item, index) in abilities" :key="index">
              <span class="highlight">{{ index + 1 }}.</span>
              {{ item.text }}
              <span v-if="item.tags.length" class="highlight">
                ({{ item.tags.join(', ') }})
              </span>
            </li>
          </ol>
        </div>
      </div>
    </section>

  <UserStoriesAccordion />
</template>

<script setup>
// import RolesSection from '@/components/UseCases/RolesSection.vue';
import UserStoriesAccordion from '@/components/UserStoriesAccordion.vue';
import ListGraphic from '@/components/ListGraphic.vue';

const abilities = [
  { text: 'Understand and visualize security control and capability coverage for techniques of interest', tags: ['SE', 'ISSO'] },
  { text: 'Assess how applying security controls and security capabilities can protect, detect, and respond to specific adversary behaviors of interest', tags: ['SE', 'ISSO'] },
  { text: 'Expanded vocabulary for describing adversary behaviors in an incident to leverage ATT&CK’s full range of TTPs when describing adversary activities during a security event.', tags: ['IR', 'ISSO'] },
  { text: 'Enhanced analysis of adversary behaviors through customized control selection for the protection from, detection of, and response to adversary activities and historical incident information.', tags: ['CISO', 'ISSO', 'SOC', 'SE'] },
  { text: 'Enable alignment of policies/controls/governance with defenses against adversary behaviors; leveraging incident information and adversary behavior to provide a holistic view from detailed descriptions in ATT&CK.', tags: ['CISO', 'SOC'] },
  { text: 'Streamline integration of threat-informed defense and incident reports into security operations. Use the ATT&CK framework to describe adversary behaviors that are known to be occurring or related to a specific incident, easily leveraging incident information to inform operations.', tags: ['SOC'] },
  { text: 'Usage of the ATT&CK framework to describe the impact of unmitigated vulnerabilities when exploited and convey that information to others.', tags: ['VR', 'CTI'] },
  { text: 'Determine the set of security controls that mitigate the techniques mapped to the group or software.', tags: ['CISO', 'SOC'] },
  { text: 'Apply a comprehensive security approach to enterprise system management through built-in hardware-based security capabilities optimized through operating system and security software.', tags: ['CISO', 'EFM'] },
  { text: 'Take proactive measures to defend against the ongoing threat of cyberattacks and protect enterprise systems from known threats by implementing security measures.', tags: ['ISSO', 'SE', 'EFM', 'VR', 'CTI'] },
]
</script>

<style scoped>
ol li {
  counter-increment: list-counter;
  margin-bottom: 0.75em;
}
.highlight {
  font-weight: 700;
}
</style>
