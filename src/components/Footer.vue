<template>
  <footer id="footer" class="footer">
    <div class="footer-content">
      <div class="m-5">
        <div class="row p-5">
          <!-- Mission -->
          <div class="col-lg-6 col-md-12 footer-info">
            <NuxtLink to="/" class="logo d-flex align-items-center">
              <img src="/img/mappings_explorer_header_logo_h60.png" alt="Mappings Explorer" />
            </NuxtLink>
            <p>
              The <a href="https://ctid.mitre.org/" target="_blank">Center for Threat‑Informed Defense</a>
              is a non‑profit, privately funded research and development organization.
              Our mission is to advance the state of the art and the state of the practice in threat‑informed defense globally.
            </p>
            <div class="d-flex mt-3 gap-4">
              <a href="https://ctid.mitre.org/" target="_blank">
                <img src="/img/mitre-logo.png" alt="CTID logo" style="height:25px" />
              </a>
              <div class="social-links d-flex">
                <a href="mailto:ctid@mitre.org?subject=Mappings%20Explorer"><i class="bi bi-envelope"></i></a>
                <a href="https://linkedin.com/showcase/center-for-threat-informed-defense"><i class="bi bi-linkedin"></i></a>
                <a href="https://youtube.com/playlist?list=PLALq3Th79NnpUkRy8TUYVBKvysCp9xwNh"><i class="bi bi-youtube"></i></a>
                <a href="https://github.com/center-for-threat-informed-defense/mappings-explorer"><i class="bi bi-github"></i></a>
              </div>
            </div>
          </div>

          <!-- About -->
          <div class="col-lg-2 col-6 footer-links">
            <h4>About</h4>
            <ul>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/about/">Overview</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/about/methodology/">Methodology</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/about/related-projects/">Related Projects</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/about/scoring/">Scoring Rubric</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/about/use-cases/">Use Cases</NuxtLink></li>
            </ul>
          </div>

          <!-- ATT&CK Objects -->
          <div class="col-lg-2 col-6 footer-links">
            <h4>ATT&CK Objects</h4>
            <ul>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/attack/matrix/">Matrix</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/attack/attack-10.1/domain-enterprise/tactics/">Tactics</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/attack/attack-10.1/domain-enterprise/techniques/">Techniques</NuxtLink></li>
            </ul>
          </div>

          <!-- Mappings Frameworks -->
          <div class="col-lg-2 col-6 footer-links">
            <h4>Mappings Frameworks</h4>
            <ul>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/">About Mappings</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/aws/">Amazon Web Services (AWS)</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/azure/">Azure</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/kev/">Known Exploited Vulnerabilities</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/gcp/">Google Cloud Platform (GCP)</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/intel-vpro/">Intel vPro</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/nist/">NIST 800‑53</NuxtLink></li>
              <li><i class="bi bi-dash"></i> <NuxtLink to="/external/veris/">VERIS</NuxtLink></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </footer>
</template>

<script setup>
</script>

<style scoped>
.footer { background:#212c5e; color:#fff; font-size:.9rem; }
.footer-content { padding:60px 0; }
.footer-info p { margin-top:1rem; }
.footer-links h4 { font-size:1.25rem; font-weight:600; margin-bottom:.5rem; }
.footer-links ul { list-style:none; padding:0; }
.footer-links li { margin:8px 0; display:flex; align-items:center; }
.footer-links i { margin-right:8px; color:var(--color-secondary); }

a { text-decoration: underline; color:#fff; transition:.2s; }
.footer-links a:hover { color:var(--color-primary); }
.social-links a { background:var(--color-primary); width:32px; height:32px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; margin-right:10px; color:var(--color-default); transition:.2s; }
.social-links a:hover { background:#38618e; }
</style>
