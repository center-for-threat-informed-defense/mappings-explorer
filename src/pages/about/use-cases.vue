<template>
  <section id="header-container" class="header-container gray-bg">
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

    <ListGraphic
      title="Use Cases"
      :items-per-row="3"
      :elements="useCases"
    />
  </section>
  <section id="use-cases">
      <div class="container col-lg-8 offset-lg-2 " >
        <div class="section-header">
          <h2>Usage</h2>
          <p style="margin-bottom: 1em;">
            The Mappings Explorer website enables the following essential abilities:
          </p>
        </div>
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
    </section>
    <section class="gray-bg">
      <div class="container col-lg-8 offset-lg-2" >
        <div class="section-header">
          <h2>User Stories</h2>
          <p>
            This section describes user stories for the Mappings Explorer website based on the roles identified
            above. These user stories are expressed as the who, what, and why, with a short exploration of how a
            user story may be achieved. This is not meant to be a comprehensive list, but rather examples to
            demonstrate how Mappings Explorer could be used.
          </p>
        </div>
      
        <UserStoriesAccordion :items="stories" />
      </div>
  </section>
</template>

<script setup>
// import RolesSection from '@/components/UseCases/RolesSection.vue';
import UserStoriesAccordion from '@/components/UserStoriesAccordion.vue';
import ListGraphic from '@/components/ListGraphic.vue';

const stories = [
  {
    id: 1,
    role: 'IR professional',
    title: 'I want to ensure I have a complete picture of an active security incident.',
    body: 'Use Mappings Explorer as a joint framework to comprehensively describe security events at a flexible level. At a very low level, the ATT&CK mappings allow incident response professionals to understand the details of adversary activities, thus creating a fingerprint of the event. This fingerprint can provide an analysis of the attacker’s tactics, techniques, and procedures (TTPs), which can assist in real-time decision making and activating responsive functionality in existing tools. Additionally, such an analysis can assist responders in looking for additional TTP artifacts that may typically coexist with currently observed activity.'
  },
  {
    id: 2,
    role: 'CISO',
    title: 'I want to understand gaps that exist in mitigation strategies to better assess enterprise risk.',
    body: 'Use the mapped security controls and capabilities to determine which mitigation strategies are most effective against techniques associated with adversarial activities, and which protective security controls or cyber solutions are needed to improve cyber defense. While individual mappings can assist in the prevention of attack recurrence based on similar TTPs, this collection of mappings can be used to guide strategic direction. The mappings repository provides a guide for an organization’s security program to use to be effective in the current threat landscape. Gaps in process or governance can then be addressed, and continuous monitoring activities can then be implemented or improved commensurate with the gaps and risks in security control coverage.'
  },
  {
    id: 3,
    role: 'CISO',
    title: 'I want to understand risk within my organization’s systems associated with specific real-world threats and available countermeasures to those threats.',
    body: 'The ATT&CK Navigator visualization of security capability mapping resources can be customized to give the user choice of contextual grouping (group, software, even tactic) and then used to identify security controls that provide protection from adversarial techniques associated with specific real-world threats and adversary behaviors. Determine which mitigation strategies are most effective, identify residual risks, and develop and implement compensating controls to improve cyber defense and protect from the most damaging attacks.'
  },
  {
    id: 4,
    role: 'ISSO',
    title: 'I want to provide input to system developers regarding security requirements and security engineering practices to incorporate to defend against adversary activity.',
    body: 'With control mappings implemented at a technique level, a mapping from a security control or capability to a technique conveys at least partial protection from, detection of, or response to the given technique. Alongside organizational controls the mappings provide an understanding of which security controls to consider selecting to protect systems against specific threats; and in turn support the SE, system developers, and information system owner’s selection and implementation of security controls that secure systems and mitigate cyber attacks.'
  },
  {
    id: 5,
    role: 'ISSO',
    title: 'I want to assess risk by understanding security control coverage in mitigating techniques associated with adversarial behavior.',
    body: 'Following the mappings to the associated techniques can provide context for which security controls and capabilities provide mitigation or protection from those techniques. In the context of this website, mapped “coverage” of a set of techniques does not mean complete protection, but rather that the given controls provide some mitigation against the successful execution of the mapped techniques. The mappings support the CISO/ISSM in reviewing the adequacy of risk and gaps in overall threat defense; and identify which additional security controls are needed to mitigate cyber attacks.'
  },
  {
    id: 6,
    role: 'SOC Analyst',
    title: 'I want to understand gaps in cyber defense and entry points where attackers may exploit systems.',
    body: 'The mappings provide an overview of existing cyber defensive coverage of categorized against adversarial behaviors. Gaps in security capability coverage and entry points can then be measured and assessed to determine what additional coverage is needed to mitigate threats. This in turn is used to inform the design, build, and implementation of appropriate cyber defenses for the organization’s systems and networks.'
  },
  {
    id: 7,
    role: 'SOC Analyst',
    title: 'I want to understand what security solutions are needed to improve cyber defense against a given group or software.',
    body: 'Gaps in cyber defense coverage and entry points can be visualized through the ATT&CK Navigator. View the set(s) of security capabilities mapped to techniques and then use “contextual grouping” to filter for the Groups or Software of interest. Analysts and defenders can better identify and understand protections available for common software usage or behaviors across multiple groups to map defenses more effectively. In addition, understanding how multiple groups use the same technique behavior allows analysts to focus on developing impactful defenses that span many types of threats and address adversaries’ evolving capabilities.'
  },
  {
    id: 8,
    role: 'SE',
    title: 'I want to select and tailor capabilities and security controls to defend against specific threats and reduce residual risk to the organization.',
    body: 'Mappings define a relationship between a security control or capability to a technique, and address how they offer protection from, detection of, or response to a given adversary behavior. Use the customizable searches to identify security controls and capabilities mapped to threats of interest, and what adversary behaviors can be mitigated by implementing those controls. Apply that information and work with the ISSO to understand residual risk in security control coverage to better align cyber defense to address adversary behaviors through the selection and tailoring of suitable controls for a given information system.'
  },
  {
    id: 9,
    role: 'VR',
    title: 'I want to analyze the effects of unmitigated vulnerabilities and exploits, to convey impact and inform risk management.',
    body: 'Compare the collection of security control and capability mappings with an organization’s vulnerability reports tied to adversary behaviors to identify unmitigated TTP artifacts and establish an understanding of the current threat landscape. Analyze and convey detailed threat and vulnerability information to develop playbooks for adversary emulation and defensive cyber operations teams. Use the common taxonomy of the ATT&CK framework and mapped security information as a tool to describe the effects of unmitigated vulnerabilities in terms of risks to the organization to inform risk mitigation decisions.'
  },
  {
    id: 10,
    role: 'CTI Analyst',
    title: 'I want to recommend countermeasures to address changes in the threat landscape based on assessments of adversary behavior and potential weaknesses.',
    body: 'Customizing control mappings to align with organizational security posture exposes gaps in protection, detection, or response to adversary behaviors, and represents an overall understanding of organizational security posture. Use the ATT&CK framework to understand what indicators and behaviors correspond to threat actors and groups to visualize and track changes in the threat landscape. Understand what adversary behaviors (ATT&CK techniques) are mitigated by reviewing the mapped security capabilities and sharing those findings and recommendations with security teams, towards implementing a customized set of security controls to counteract specific threats and address gaps in defensive coverage.'
  },
  {
    id: 11,
    role: 'EFM',
    title: 'I want to recommend procuring systems for streamlined integration and management.',
    body: 'Compare an organization’s necessary platforms and products for its fleet of enterprise systems with the collection of security control and capability mappings to identify countermeasures available at the hardware and software levels that provide protection from adversarial threats.'
  }
];


const useCases = [
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
      ]

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
