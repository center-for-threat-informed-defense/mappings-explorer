
export default defineNuxtConfig({
  compatibilityDate: '2025-03-03', // Mappings are not the most recent
  devtools: { enabled: true },
  ssr: true,
    nitro: {
        static: true,
        prerender: { // TODO: Right now all routes are prerendered-- in the future if we were to add mappings pages, we might only prerender everything up to frameworks pages (everything besides mappings pages)
            crawlLinks: true,
            routes: ['/'],
            ignore: [],
        },
    },
  css: [
    'bootstrap/dist/css/bootstrap.min.css',
    'bootstrap-icons/font/bootstrap-icons.css',
    '~/assets/css/main.css'
  ]
})
