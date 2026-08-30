import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { ForensicProvider } from "@/components/forensic-context";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";

export const metadata: Metadata = {
  title: "ChainMail | AI Email Threat Detection, GeoLocation & Forensic Intelligence",
  description: "Advanced cybersecurity platform for analyzing raw email headers, transmission routing, NLP behavioral manipulation, BEC, and threat actor attribution.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className="h-full antialiased dark"
      suppressHydrationWarning
    >
      <body className="min-h-full flex flex-col font-sans cyber-grid selection:bg-cyan-500/20 selection:text-cyan-400">
        <ThemeProvider>
          <ForensicProvider>
            <Navbar />
            <main className="flex-1 pt-24 pb-16">
              {children}
            </main>
            <Footer />
          </ForensicProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
