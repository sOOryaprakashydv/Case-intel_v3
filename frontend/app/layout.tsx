import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "CaseIntel — Case-Correlated Malware Investigation Platform",
  description: "Explainable analysis, correlation, and investigation acceleration for law enforcement.",
  viewport: "width=device-width, initial-scale=1",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="flex flex-col lg:flex-row min-h-screen">
          <Sidebar />
          <main className="flex-1 min-w-0 px-4 py-6 sm:px-6 lg:px-10 lg:py-10 max-w-[1600px] mx-auto w-full">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
