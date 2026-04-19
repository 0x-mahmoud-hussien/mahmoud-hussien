export type CertificationStatus = "completed" | "in-progress" | "planned";

export type Certification = {
  title: string;
  issuer: string;
  year: string;
  verifyUrl: string | null;
  status: CertificationStatus;
};

export const certifications: Certification[] = [
  {
    title: "TryHackMe SOC Level 1",
    issuer: "TryHackMe",
    year: "2026",
    verifyUrl: "https://tryhackme.com/certificate/THM-ABGE8YCQYT",
    status: "completed",
  },

  // Uncomment when earned:
  // {
  //   title: "Google Cybersecurity Certificate",
  //   issuer: "Google / Coursera",
  //   year: "2024",
  //   verifyUrl: null,
  //   status: "planned",
  // },
  // {
  //   title: "CompTIA Security+",
  //   issuer: "CompTIA",
  //   year: "2025",
  //   verifyUrl: null,
  //   status: "planned",
  // },
];
