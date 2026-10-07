import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Rally — A little friendly competition",
  description: "Take a break, grab a paddle, and play a quick game of ping-pong. Your next rally starts here.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
