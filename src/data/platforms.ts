export const platforms = {
  TryHackMe: {
    label: "TryHackMe",
    short: "THM",
    color: "#86de72",
    bg: "rgba(134,222,114,0.1)",
    border: "rgba(134,222,114,0.25)",
    url: "https://tryhackme.com",
  },
  CyberDefenders: {
    label: "CyberDefenders",
    short: "CD",
    color: "#58d6c8",
    bg: "rgba(88,214,200,0.1)",
    border: "rgba(88,214,200,0.25)",
    url: "https://cyberdefenders.org",
  },
  HackTheBox: {
    label: "HackTheBox",
    short: "HTB",
    color: "#9fef00",
    bg: "rgba(159,239,0,0.08)",
    border: "rgba(159,239,0,0.25)",
    url: "https://hackthebox.com",
  },
  picoCTF: {
    label: "picoCTF",
    short: "pico",
    color: "#f7c948",
    bg: "rgba(247,201,72,0.1)",
    border: "rgba(247,201,72,0.25)",
    url: "https://picoctf.org",
  },
} as const;

export type Platform = keyof typeof platforms;
