import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "EchoCurve - SRS Practice",
  description: "Audio-first spaced repetition practice for language learning.",
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
