<!-- TODO: Fix this file -->
<template>
  <section id="user-stories" class="gray-bg">
    <div class="container col-lg-8 offset-lg-2" data-aos="fade-up">
      <div class="section-header">
        <h2>User Stories</h2>
        <p>
        This section describes user stories for the Mappings Explorer website based on the roles identified
          above. These user stories are expressed as the who, what, and why, with a short exploration of how a
          user story may be achieved. This is not meant to be a comprehensive list, but rather examples to
          demonstrate how Mappings Explorer could be used.
        </p>
      </div>
      <div class="accordion accordion-flush" id="stories-accordion">
        <template v-for="story in stories" :key="story.id">
          <div class="accordion-item">
            <h2 class="accordion-header" :id="`stories-head-${story.id}`">
              <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                :data-bs-target="`#stories-body-${story.id}`" :aria-controls="`stories-body-${story.id}`">
                <div>
                  <span class="highlight">As a {{ story.role }},</span> {{ story.title }}
                </div>
              </button>
            </h2>
            <div :id="`stories-body-${story.id}`" class="accordion-collapse collapse" :aria-labelledby="`stories-head-${story.id}`"
              data-bs-parent="#stories-accordion">
              <div class="accordion-body">
                {{ story.body }}
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>
  </section>
</template>

<script setup>
const stories = [
  {
    id: 1,
    role: 'IR professional',
    title: 'I want to ensure I have a complete picture of an active security incident.',
    body: 'Use Mappings Explorer as a joint framework to comprehensively describe security events at a flexible level...'
  },
  {
    id: 2,
    role: 'CISO',
    title: 'I want to understand gaps that exist in mitigation strategies to better assess enterprise risk.',
    body: 'Use the mapped security controls and capabilities to determine which mitigation strategies are most effective...'
  },
  // Add all other stories here...
]
</script>

<style scoped>
.accordion-button div {
  font-weight: 700;
}
</style>
