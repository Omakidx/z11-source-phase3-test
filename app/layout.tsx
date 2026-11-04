import type { Metadata } from "next";
import type { ReactNode } from "react";

import "./page.css";

export const metadata: Metadata = {
  title: "Z11 Phase 4 Vercel Fixture",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
