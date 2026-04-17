# Mahmoud Hussien — Portfolio & Writeups

Personal website built with Astro where I publish cybersecurity writeups, notes, and portfolio updates.

## Run locally

```bash
npm install
npm run dev
```

Then open `http://localhost:4321`.

## Adding a new writeup

1. Create a new `.md` file in `src/content/writeups/`.
2. Add the required frontmatter (see the schema in `src/content.config.ts`).
3. Write your writeup in Markdown.

## Updating site content

Most site content (profile, skills, stats, links) lives in `src/data/` and is rendered throughout the site from there.
