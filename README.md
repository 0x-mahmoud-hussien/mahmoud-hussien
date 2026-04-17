# Mahmoud Hussien — Portfolio & Writeups

This is **my personal** portfolio + cybersecurity writeups site, built with Astro. It’s where I publish lab walkthroughs, notes, and updates to my portfolio content.

## Quick Start

1. Clone the repository
2. Install dependencies: `npm install`
3. Run the dev server: `npm run dev`
4. Open `http://localhost:4321`

## How to Deploy

### Option A: Vercel (Recommended)
1. Import this repository into your Vercel dashboard.
2. Vercel will automatically detect the Astro framework and apply the configurations in `vercel.json` and `astro.config.mjs`.

### Option B: GitHub Pages
1. Go to your GitHub repository Settings > Pages.
2. Under "Source", select "GitHub Actions" to use the pre-configured `.github/workflows/deploy.yml`.
3. In `astro.config.mjs`, ensure you uncomment and set the `base` array configuration to `'/your-repo-name'`.

## Important TODOs Before Deploy
- [ ] Replace `TODO_GITHUB_USERNAME` in `src/data/profile.ts`
- [ ] Replace `TODO_LINKEDIN` in `src/data/profile.ts`
- [ ] Replace `TODO_THM_USERNAME` in `src/data/profile.ts`
- [ ] Replace `TODO_CD_USERNAME` in `src/data/profile.ts`
- [ ] Replace `TODO_EMAIL` in `src/data/profile.ts`
- [ ] Update `site` URL in `astro.config.mjs` after deploying (required for sitemap + canonical URLs)
- [ ] Update `robots.txt` sitemap URL to match deployed domain
- [ ] Add real certificate URLs in `src/data/certifications.ts`
- [ ] Share journey repo URL to replace sample writeups with real ones

## Adding a new writeup
1. Create a new `.md` file in `src/content/writeups/`.
2. Add the required frontmatter block at the top, referencing the current `src/content.config.ts` schema format.
3. Write your writeup using standard Markdown!

## Update Personal Info
All your skills, profiles, stats, and platform badges are populated dynamically from `src/data`. Update these source files and the UI will reflect all the changes across the app.
