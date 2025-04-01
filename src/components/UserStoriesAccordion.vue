<template>
      <div class="accordion">
        <div
          v-for="(item, index) in items"
          :key="index"
          class="accordion-item"
        >
          <div
            class="accordion-header"
            @click="toggle(index)"
            :aria-expanded="isOpen(index).toString()"
          >
            <p> 
              <span class="highlight">As a {{ item.role.trim() }}, </span>
              <span>{{ item.title }}</span>
            </p>
            <i
              :class="['bi', isOpen(index) ? 'bi-chevron-up' : 'bi-chevron-down', 'accordion-icon']"
            ></i>
          </div>
          <div
            v-show="isOpen(index)"
            class="accordion-body"
          >
            {{ item.body }}
          </div>
        </div>
      </div>
</template>

<script>
export default {
  props: {
    items: {
      type: Array,
      required: true
    }
  },
  data() {
    return {
      openIndex: null
    };
  },
  methods: {
    toggle(index) {
      this.openIndex = this.openIndex === index ? null : index;
    },
    isOpen(index) {
      return this.openIndex === index;
    }
  }
};
</script>

<style scoped>

.accordion {
  display: flex;
  flex-direction: column;
  max-width: 1000px; 
  width: 100%;
  background-color: white;
}

.accordion-item {
  background-color: white;
  border: 1px solid #ddd;
  border-radius: 5px;
}

.accordion-header {
  display: flex;
  justify-content: space-between;
  background-color: white;
  padding: 1rem;
  cursor: pointer;
  font-weight: bold;
  border: none;
  width: 100%;
  text-align: left;
}

.accordion-body {
  text-align: left;
}

.accordion-icon {
  font-size: 1.2rem;
}

.accordion-header:hover .accordion-icon {
  transform: scale(1.1);
}
</style>
