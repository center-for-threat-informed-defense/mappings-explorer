# Vue 3 Nuxt-based Mappings Explorer

This is the start of a rebuild of the Mappings Explorer site to migrate the previous Jinja/Python based site to one using Nuxt and Vue. 
See below for how to run and generate a static version of the site, as well as future work.

## Setup

Make sure to install dependencies:

```bash
# npm
npm install

# pnpm
pnpm install

# yarn
yarn install

# bun
bun install
```

## Development Server

Start the development server on `http://localhost:3000`:

```bash
# npm
npm run dev

# pnpm
pnpm dev

# yarn
yarn dev

# bun
bun run dev
```

## Production

```

Build a static application for production:

```bash
# npm
npm run preview
```

You can can then see a sample of the entire static Mappings Explorer site in `.output/public`
You can locally preview it using npx as shown below or by any means of your choice
```bash
npx serve .output/public 
```  


Check out the [deployment documentation](https://nuxt.com/docs/getting-started/deployment) for more information.

# Future Work

- Search bar functionality
- User stories dropdown (Use Cases about page)
- Methodology child pages
- Download Mapping Artifacts (Will be worked out when we figure out how mappings scripts are ported over)
- Attack pages (matrix, tactics, techniques) -- will need to port over scripts from old site
- Clean up some of the CSS
- Mobile Support
- Mappings/Capabilities data
    - Right now, the data on the frameworks pages are loaded through a fake "api" which accesses the mappings data in public/data
        - using this api "hack" allows us to have the data in the 
    - Some of the scripts need to be ported over for this
    - In future work we might want to have the client side generate a page for each mapping (these would not be prerendered like the other pages though)
        - There are a few ways we can look into doing this. For example, the prerender does not generate data which is directly accessed from public (e.g. how the the mappings table is rendered right now--you can see that on the prerendered frameworks pages, like `.output/external/gcp/index.vue`, the framework data is prerendered but not the mappings)


