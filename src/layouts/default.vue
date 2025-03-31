<template>
    <div id="app">
      <!-- Site‑wide Header -->
      <Header
        attack_version="15.1"
        attack_domain="Enterprise"
        :versions="['v15.1']"
        control="Mappings Explorer"
        control_version="1.0"
        previous_link="/change-version"
      />
  
      <!-- Page content -->
      <main id="page-content">
        <NuxtPage />
      </main>
  
      <!-- Site‑wide Footer -->
      <Footer :url_prefix="urlPrefix" />
    </div>
  </template>
  
  <script setup>
  import Header from '~/components/Header.vue'
  import Footer from '~/components/Footer.vue'
  const urlPrefix = '/'
  </script>
  
  <style>
  
  /* global reset */
  html, body {
    margin: 0;
    padding: 0;
  }

  /* Flex container so footer sits at bottom */
  #app {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }
  
  #page-content {
    flex: 1;
    padding-top: 100px; /* Adjust based on header height */
  }
  </style>
  