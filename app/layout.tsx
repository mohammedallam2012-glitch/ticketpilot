import type { ReactNode } from "react";

export const metadata = {
  title: "TicketPilot",
  description:
    "Independent Ticket Reseller Inventory, Multi-Marketplace Listing Tracker & Duplicate-Sale Safety SaaS",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
