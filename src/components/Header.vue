<template>
  <div class="header-container">
    <!-- Logo -->
    <NuxtLink to="/" class="logo d-flex align-items-center">
      <img src="/public/img/mappings_explorer_header_logo_h60.png" alt="Mappings Explorer" />
    </NuxtLink>

    <!-- Mobile nav toggles -->
    <i class="mobile-nav-toggle mobile-nav-show bi bi-list" @click="toggleMobileNav"></i>
    <i class="mobile-nav-toggle mobile-nav-hide d-none bi bi-x" @click="toggleMobileNav"></i>

    <!-- Navigation Menu -->
    <nav id="navbar" class="navbar" :class="{ 'mobile-active': mobileActive }">
      <ul>
        <!-- ABOUT Dropdown -->
        <li class="dropdown">
          <NuxtLink to="/about/">
            <span>ABOUT</span>
            <i class="bi bi-chevron-down dropdown-indicator"></i>
          </NuxtLink>
          <ul>
            <li><NuxtLink to="/about/">Overview</NuxtLink></li>
            <li><NuxtLink to="/about/use-cases/">Use Cases</NuxtLink></li>
            <li><NuxtLink to="/about/methodology/">Mapping Methodology</NuxtLink></li>
            <li><NuxtLink to="/about/scoring/">Scoring Rubric</NuxtLink></li>
            <li><NuxtLink to="/about/related-projects/">Related Projects</NuxtLink></li>
          </ul>
        </li>

        <!-- ATT&CK Objects Dropdown -->
        <li class="dropdown">
          <NuxtLink to="/attack/matrix/">
            <span>ATT&amp;CK OBJECTS</span>
            <i class="bi bi-chevron-down dropdown-indicator"></i>
          </NuxtLink>
          <ul>
            <li><NuxtLink to="/attack/matrix/">Matrix</NuxtLink></li>
            <li><NuxtLink to="/attack/attack-10.1/domain-enterprise/tactics/">Tactics</NuxtLink></li>
            <li><NuxtLink to="/attack/attack-10.1/domain-enterprise/techniques/">Techniques</NuxtLink></li>
          </ul>
        </li>

        <!-- Mapping Frameworks Dropdown -->
        <li class="dropdown">
          <NuxtLink to="/external">
            <span>MAPPING FRAMEWORKS</span>
            <i class="bi bi-chevron-down dropdown-indicator"></i>
          </NuxtLink>
          <ul>
            <li><NuxtLink to="/external">About Mappings</NuxtLink></li>
            <li><NuxtLink to="/external/aws/">Amazon Web Services (AWS)</NuxtLink></li>
            <li><NuxtLink to="/external/azure/">Azure</NuxtLink></li>
            <li><NuxtLink to="/external/kev/">Known Exploited Vulnerabilities</NuxtLink></li>
            <li><NuxtLink to="/external/gcp/">Google Cloud Platform (GCP)</NuxtLink></li>
            <li><NuxtLink to="/external/intel-vpro/">Intel vPro</NuxtLink></li>
            <li><NuxtLink to="/external/nist/">NIST 800-53</NuxtLink></li>
            <li><NuxtLink to="/external/m365/">M365</NuxtLink></li>
            <li><NuxtLink to="/external/veris/">VERIS</NuxtLink></li>
          </ul>
        </li>

        <!-- Search Box -->
        <li class="nav-search">
          <div class="input-group">
              <input
                type="search"
                id="nav-search-input"
                class="form-control bg-transparent text-white "
                placeholder="Search"
              />
              <button
                class="btn btn-transparentp-2"
              >
                <img src="/public/img/search-white.svg" alt="search" />
              </button>
            </div>
          </li>
      </ul>
    </nav>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const mobileActive = ref(false)
const router = useRouter()

function toggleMobileNav() {
  mobileActive.value = !mobileActive.value
}

</script>

<style scoped>

.header-container {
  background-color: #212c5e; 
  position: fixed;
  top: 0;
  width: 100%;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 15px 60px;
  min-height: 100px;
  box-sizing: border-box;
}

.logo img {
  max-height: 40px; 
  margin-right: 10px; 
}


/* Mobile nav toggles (hamburger icons) */
.mobile-nav-toggle {
  display: none;
  font-size: 28px;
  color: #fff;
  cursor: pointer;
}

/* Nav styling */
.navbar {
  display: flex;
  align-items: center;
  margin-right: 20px; 
}

.navbar ul {
  display: flex;
  align-items: center;
  margin: 0;
  padding: 0;
}

.navbar ul li {
  position: relative;
  margin-left: 30px; 
}


.navbar a,
.navbar a:visited {
  color: #fff;
  text-decoration: none;
  font-weight: 500;
  text-transform: uppercase; 
  font-size: 0.85rem;       
  letter-spacing: 0.05em;  
  font-family: var(--font-default, "Roboto Condensed", sans-serif);
}

#nav-search-input::placeholder {
  color: #fff !important;
  opacity: 1; 
}


.navbar ul li.dropdown {
  position: relative;
}

/* Dropdown menu styling */
.dropdown > ul {
  position: absolute;
  top: 100%;
  left: 0;
  background: #212c5e;
  padding: 8px 0;
  margin: 0;
  list-style: none;
  display: none;
  min-width: 180px; 
  border: 1px solid rgba(255, 255, 255, 0.1); 
}

.dropdown:hover > ul {
  display: block;
}

.dropdown-indicator {
  margin-left: 5px;
  font-size: 0.8rem; 
}

.dropdown ul li {
  margin: 0;
}

.dropdown ul li a {
  display: block;
  padding: 8px 15px;
  white-space: nowrap;
  font-size: 0.8rem;
  letter-spacing: 0.03em;
}

.nav-search {
  display: flex;
  align-items: center;
  margin-left: 40px;
}

.input-group {
  display: flex;
  align-items: center;
  border: 1px solid #fff;
  border-radius: 4px;
  overflow: hidden;
  background-color: transparent;
}

.search-input {
  background-color: transparent;
  border: none;
  padding: 6px 10px;
  flex: 1;
  color: #fff;
  font-size: 0.8rem;
}

.search-input:focus {
  outline: none;
}

.input-group-text {
  background-color: transparent;
  border: none;
  cursor: pointer;
  padding: 6px 10px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.input-group-text img {
  height: 18px;
}

/* MOBILE BREAKPOINTS */
@media (max-width: 992px) {
  .mobile-nav-toggle {
    display: block;
  }

  .navbar {
    position: fixed;
    top: 0;
    right: -100%;
    width: 100%;
    max-width: 300px;
    height: 100%;
    background-color: #212c5e;
    transition: 0.3s;
    z-index: 9999;
    padding-top: 60px;
    flex-direction: column;
    align-items: flex-start;
    margin-right: 0;
  }

  .navbar.mobile-active {
    right: 0;
  }

  .navbar ul {
    flex-direction: column;
    width: 100%;
  }

  .navbar ul li {
    margin: 15px 0;
  }

  .nav-search {
    width: 100%;
    padding: 0 20px;
  }
}
</style>
