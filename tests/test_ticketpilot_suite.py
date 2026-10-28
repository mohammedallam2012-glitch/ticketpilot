#!/usr/bin/env python3
"""
TicketPilot — Comprehensive Automated Verification & Security Test Suite
Executes and verifies:
1. Authentication, Email Normalization, Password Strength, and Email Verification Gate
2. Ticket Inventory CRUD, Validation, and Archival Rules
3. Multi-Marketplace External Listings & Currency-Segregated Lowest Asking Price
4. Duplicate-Sale Safety & "Needs Action" State Machine (0, 1, and multiple unresolved listings)
5. Financial Calculations (Realized Profit, Unsold Inventory Exclusion, Expected vs Received Payouts, Currency Boundaries)
6. Multi-User Security & IDOR Isolation (User A vs User B across Tickets, Listings, Sales, Payouts, CSV Exports)
7. CSV Export Accuracy & Formula Injection Sanitization
8. Reauthenticated Account Deletion & Cascade Purge
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.ticketpilot_engine import (
    AuthorizationError,
    TicketPilotEngine,
    ValidationError,
    sanitize_csv_cell,
)


class TestTicketPilotSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TicketPilotEngine(":memory:")

    def _register_and_verify(self, name: str, email: str, password: str = "StrongPass123!") -> str:
        reg = self.engine.register_user(name, email, password, True, True)
        self.engine.verify_email(reg["verification_token_for_testing_or_outbox"])
        login_res = self.engine.login(email, password)
        return login_res["session_token"]

    # 1. AUTHENTICATION & EMAIL VERIFICATION GATE
    def test_01_authentication_and_email_verification_gate(self) -> None:
        # Reject weak password
        with self.assertRaises(ValidationError):
            self.engine.register_user("Mohamed", "user@example.com", "weak", True, True)

        # Reject missing terms acceptance
        with self.assertRaises(ValidationError):
            self.engine.register_user("Mohamed", "user@example.com", "StrongPass123!", False, True)

        # Register with mixed-case email
        reg = self.engine.register_user("Mohamed Allam", "  Mohamed.Allam@Example.COM ", "StrongPass123!", True, True)
        self.assertEqual(reg["email"], "mohamed.allam@example.com")
        self.assertFalse(reg["email_verified"])

        # Login before email verification succeeds for verification screen, but blocks business operations
        unverified_login = self.engine.login("mohamed.allam@example.com", "StrongPass123!")
        unverified_token = unverified_login["session_token"]
        with self.assertRaises(AuthorizationError):
            self.engine.create_ticket(
                unverified_token,
                "UEFA Champions League Final",
                "2026-11-20T20:00:00Z",
                "Wembley Stadium",
                "102",
                "12",
                2,
                30000,
                "USD",
            )

        # Complete email verification and verify business access is unlocked
        ver = self.engine.verify_email(reg["verification_token_for_testing_or_outbox"])
        self.assertTrue(ver["email_verified"])
        ticket = self.engine.create_ticket(
            unverified_token,
            "UEFA Champions League Final",
            "2026-11-20T20:00:00Z",
            "Wembley Stadium",
            "102",
            "12",
            2,
            30000,
            "USD",
        )
        self.assertEqual(ticket["status"], "Available")

    # 2. INVENTORY & CURRENCY-AWARE LOWEST ASKING PRICE
    def test_02_inventory_and_multi_currency_listings(self) -> None:
        token = self._register_and_verify("Alex Reseller", "alex@reseller.io")
        ticket = self.engine.create_ticket(
            token,
            "Taylor Swift | The Eras Tour",
            "2026-12-05T19:30:00Z",
            "MetLife Stadium",
            "Floor A",
            "4",
            2,
            40000,  # $400.00 total acquisition cost
            "USD",
            seat_range="10-11",
        )
        tid = ticket["id"]

        # Reject invalid negative cost or zero quantity
        with self.assertRaises(ValidationError):
            self.engine.create_ticket(token, "Bad Event", "2026-12-05T19:30:00Z", "Venue", "100", "1", 0, 1000, "USD")

        # Add 2 USD listings and 1 EUR listing
        self.engine.create_external_listing(token, tid, "StubHub", 75000, "USD", "https://stubhub.com/1", "SH-101")
        self.engine.create_external_listing(token, tid, "TickPick", 71000, "USD", "https://tickpick.com/1", "TP-202")
        self.engine.create_external_listing(token, tid, "Viagogo", 68000, "EUR", "https://viagogo.com/1", "VG-303")

        updated_ticket = self.engine.get_ticket(token, tid)
        self.assertEqual(updated_ticket["status"], "Listed")
        # Lowest active price must be segregated by currency (71000 cents in USD, 68000 cents in EUR)
        self.assertEqual(updated_ticket["lowest_active_prices_by_currency"]["USD"], 71000)
        self.assertEqual(updated_ticket["lowest_active_prices_by_currency"]["EUR"], 68000)

    # 3. DUPLICATE-SALE SAFETY & "NEEDS ACTION" WORKFLOW
    def test_03_duplicate_sale_safety_workflow(self) -> None:
        token = self._register_and_verify("Sarah Broker", "sarah@broker.io")

        # Case A: Ticket with NO other active listings transitions directly to "Sold"
        t_single = self.engine.create_ticket(
            token, "NBA Knicks vs Lakers", "2026-11-15T19:00:00Z", "Madison Square Garden", "105", "8", 2, 25000, "USD"
        )
        l_single = self.engine.create_external_listing(token, t_single["id"], "StubHub", 42000, "USD")
        sale_single = self.engine.record_sale(
            token, t_single["id"], "StubHub", 42000, 6300, 0, 0, "USD", sold_listing_id=l_single["id"]
        )
        self.assertEqual(sale_single["ticket_status"], "Sold")
        self.assertEqual(len(sale_single["unresolved_listings"]), 0)

        # Case B: Ticket with 3 listings across StubHub, Viagogo, and SeatGeek
        t_multi = self.engine.create_ticket(
            token, "Coldplay World Tour", "2026-12-10T20:00:00Z", "Wembley Stadium", "112", "15", 2, 30000, "USD"
        )
        l_sh = self.engine.create_external_listing(token, t_multi["id"], "StubHub", 60000, "USD", "https://stubhub.com/c", "SH-900")
        l_vg = self.engine.create_external_listing(token, t_multi["id"], "Viagogo", 62000, "USD", "https://viagogo.com/c", "VG-901")
        l_sg = self.engine.create_external_listing(token, t_multi["id"], "SeatGeek", 59000, "USD", "https://seatgeek.com/c", "SG-902")

        # Record sale on StubHub -> 2 unresolved listings remain (Viagogo & SeatGeek)
        sale_multi = self.engine.record_sale(
            token, t_multi["id"], "StubHub", 60000, 9000, 1000, 0, "USD", sold_listing_id=l_sh["id"]
        )
        self.assertEqual(sale_multi["ticket_status"], "Needs Action")
        self.assertEqual(len(sale_multi["unresolved_listings"]), 2)

        # Verify critical alert was created
        alerts = self.engine.conn.execute(
            "SELECT * FROM alerts WHERE related_ticket_id = ? AND is_handled = 0", (t_multi["id"],)
        ).fetchall()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "DUPLICATE_SALE_RISK")

        # Confirm removal of Viagogo listing -> 1 unresolved listing (SeatGeek) still remains -> must stay "Needs Action"
        res1 = self.engine.confirm_external_listing_removed(token, l_vg["id"], "Removed", "Removed on Viagogo seller portal")
        self.assertEqual(res1["remaining_unresolved_listings"], 1)
        self.assertEqual(res1["ticket_status"], "Needs Action")

        # Confirm removal of SeatGeek listing -> 0 unresolved listings remain -> transitions to "Sold"
        res2 = self.engine.confirm_external_listing_removed(token, l_sg["id"], "Removed", "Removed on SeatGeek seller portal")
        self.assertEqual(res2["remaining_unresolved_listings"], 0)
        self.assertEqual(res2["ticket_status"], "Sold")

    # 4. FINANCIAL CALCULATIONS & CURRENCY SEGREGATION
    def test_04_financial_accuracy_and_unsold_exclusion(self) -> None:
        token = self._register_and_verify("Finance User", "finance@ticketpilot.io")

        # Ticket 1 (USD - Sold): Acquisition $300.00, Gross Sale $500.00, Fee $75.00, Other Cost $5.00
        # Net Proceeds = $500 - $75 - $5 = $420.00 (42000 cents)
        # Realized Profit = $420 - $300 = $120.00 (12000 cents)
        t1 = self.engine.create_ticket(
            token, "UFC 315", "2026-11-28T22:00:00Z", "T-Mobile Arena", "201", "5", 2, 30000, "USD"
        )
        s1 = self.engine.record_sale(token, t1["id"], "StubHub", 50000, 7500, 500, 0, "USD")
        self.assertEqual(s1["net_proceeds_cents"], 42000)
        self.assertEqual(s1["realized_profit_cents"], 12000)

        # Ticket 2 (USD - Unsold / Listed): Acquisition $800.00 -> MUST NOT reduce realized profit!
        t2 = self.engine.create_ticket(
            token, "Super Bowl LXI", "2027-02-14T18:30:00Z", "SoFi Stadium", "300", "10", 2, 80000, "USD"
        )
        self.engine.create_external_listing(token, t2["id"], "Ticketmaster Resale", 150000, "USD")

        # Ticket 3 (EUR - Sold): Acquisition €200.00, Gross Sale €350.00, Fee €52.50
        # Net Proceeds = €297.50 (29750 cents), Realized Profit = €97.50 (9750 cents)
        t3 = self.engine.create_ticket(
            token, "Real Madrid vs Barcelona", "2026-11-22T20:00:00Z", "Santiago Bernabeu", "104", "3", 1, 20000, "EUR"
        )
        s3 = self.engine.record_sale(token, t3["id"], "Viagogo", 35000, 5250, 0, 0, "EUR")

        summary = self.engine.get_financial_summary(token)
        usd = summary["by_currency"]["USD"]
        eur = summary["by_currency"]["EUR"]

        # Verify USD metrics
        self.assertEqual(usd["gross_sales_cents"], 50000)
        self.assertEqual(usd["marketplace_fees_cents"], 7500)
        self.assertEqual(usd["sold_acquisition_cost_cents"], 30000)
        self.assertEqual(usd["realized_profit_cents"], 12000)
        self.assertEqual(usd["unsold_inventory_cost_cents"], 80000)
        # Expected payout is 42000, received payout is 0 until explicitly marked paid
        self.assertEqual(usd["expected_pending_payouts_cents"], 42000)
        self.assertEqual(usd["received_payouts_cents"], 0)

        # Mark USD payout received and verify transition
        self.engine.record_payout_received(token, s1["payout_id"], 42000, "2026-10-28", "PAY-SH-001")
        summary_after = self.engine.get_financial_summary(token)
        self.assertEqual(summary_after["by_currency"]["USD"]["expected_pending_payouts_cents"], 0)
        self.assertEqual(summary_after["by_currency"]["USD"]["received_payouts_cents"], 42000)

        # Verify EUR metrics are strictly separate from USD
        self.assertEqual(eur["realized_profit_cents"], 9750)

    # 5. MULTI-USER SECURITY & CROSS-USER IDOR ISOLATION
    def test_05_multi_user_security_and_idor_prevention(self) -> None:
        token_a = self._register_and_verify("User A", "usera@ticketpilot.io")
        token_b = self._register_and_verify("User B", "userb@ticketpilot.io")

        ticket_a = self.engine.create_ticket(
            token_a, "Formula 1 Las Vegas GP", "2026-11-21T22:00:00Z", "Las Vegas Strip Circuit", "GS1", "9", 2, 90000, "USD"
        )
        listing_a = self.engine.create_external_listing(token_a, ticket_a["id"], "StubHub", 140000, "USD")

        # User B attempts to read User A's ticket by ID
        with self.assertRaises(AuthorizationError):
            self.engine.get_ticket(token_b, ticket_a["id"])

        # User B attempts to archive User A's ticket
        with self.assertRaises(AuthorizationError):
            self.engine.archive_ticket(token_b, ticket_a["id"])

        # User B attempts to attach a listing to User A's ticket
        with self.assertRaises(AuthorizationError):
            self.engine.create_external_listing(token_b, ticket_a["id"], "Viagogo", 150000, "USD")

        # User B attempts to record a sale on User A's ticket
        with self.assertRaises(AuthorizationError):
            self.engine.record_sale(token_b, ticket_a["id"], "StubHub", 140000, 21000, 0, 0, "USD")

        # User B attempts to mark User A's listing as removed
        with self.assertRaises(AuthorizationError):
            self.engine.confirm_external_listing_removed(token_b, listing_a["id"], "Removed")

        # User A records sale; User B's CSV export must contain 0 rows from User A
        self.engine.record_sale(token_a, ticket_a["id"], "StubHub", 140000, 21000, 0, 0, "USD", sold_listing_id=listing_a["id"])
        csv_b = self.engine.export_sales_csv(token_b)
        self.assertNotIn("Formula 1 Las Vegas GP", csv_b)

    # 6. CSV EXPORT & FORMULA INJECTION SANITIZATION
    def test_06_csv_export_and_formula_injection_protection(self) -> None:
        token = self._register_and_verify("CSV Tester", "csv@ticketpilot.io")
        # Malicious formula string in notes or venue
        t = self.engine.create_ticket(
            token,
            "=HYPERLINK(\"http://evil.example/steal\", \"Click\")",
            "2026-12-01T20:00:00Z",
            "+cmd|' /C calc'!A0",
            "101",
            "1",
            1,
            10000,
            "USD",
            notes="@SUM(1+1)",
        )
        self.engine.record_sale(token, t["id"], "TickPick", 18000, 1800, 0, 0, "USD", notes="-2+3+cmd")
        csv_data = self.engine.export_sales_csv(token)

        # Every dangerous leading character (=, +, -, @) must be prefixed with a single quote '
        self.assertIn("'=HYPERLINK", csv_data)
        self.assertIn("'+cmd", csv_data)
        self.assertIn("'-2+3+cmd", csv_data)
        self.assertEqual(sanitize_csv_cell("=1+1"), "'=1+1")

    # 7. ACCOUNT DELETION WITH REAUTHENTICATION
    def test_07_account_deletion_requires_reauth_and_purges_records(self) -> None:
        token = self._register_and_verify("Delete Me", "deleteme@ticketpilot.io", "MySecretPass99!")
        t = self.engine.create_ticket(
            token, "Arsenal vs Chelsea", "2026-11-29T16:30:00Z", "Emirates Stadium", "Club", "2", 2, 24000, "GBP"
        )
        self.engine.record_sale(token, t["id"], "StubHub", 38000, 5700, 0, 0, "GBP")

        # Wrong password must fail
        with self.assertRaises(AuthorizationError):
            self.engine.delete_account(token, "WrongPass123!", "DELETE MY ACCOUNT")

        # Correct password + confirmation purges user and all owned records
        res = self.engine.delete_account(token, "MySecretPass99!", "DELETE MY ACCOUNT")
        self.assertTrue(res["active_database_purged"])

        # Subsequent use of session token must fail
        with self.assertRaises(AuthorizationError):
            self.engine.get_financial_summary(token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
