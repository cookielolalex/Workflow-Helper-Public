import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import "./globals.css";


export const metadata: Metadata = {
  title: "Workflow Helper",
  description: "CAD workflow capture review control plane",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <Link className="brand" href="/">
            <span className="brand-mark" aria-hidden="true">WH</span>
            <span>
              <strong>Workflow Helper</strong>
              <small>CAD knowledge capture</small>
            </span>
          </Link>
          <span className="environment-badge">MVP scaffold</span>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
