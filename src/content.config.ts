import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const writeups = defineCollection({
  loader: glob({ pattern: '**/*.{md,mdx}', base: './src/content/writeups' }),
  schema: z.object({
    title:        z.string(),
    description:  z.string(),          // 1-2 sentences shown in card
    date:         z.coerce.date(),
    platform:     z.enum(['TryHackMe', 'CyberDefenders', 'HackTheBox', 'Other']),
    difficulty:   z.enum(['Easy', 'Medium', 'Hard']),
    category:     z.enum(['Blue Team', 'Forensics', 'CTF', 'Threat Hunting', 'OSINT', 'Web', 'Crypto', 'Incident Response / DFIR']),
    tags:         z.array(z.string()),
    featured:     z.boolean().default(false),  // show on home page
    draft:        z.boolean().default(false),  // hide from listing if true
    tools:        z.array(z.string()).optional(), // tools used in this writeup
    room_url:     z.string().url().optional(),    // link to original challenge
  }),
});

export const collections = { writeups };
