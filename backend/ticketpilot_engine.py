#!/usr/bin/env python3
"""
TicketPilot — Production-Oriented Backend & Relational Database Engine
Implements:
- Relational SQLite/PostgreSQL compatible schema with Foreign Keys & constraints
- Real PBKDF2-HMAC-SHA256 password hashing, email normalization, and email verification tokens
- Strict Server-Side Authorization & Row-Level Ownership checks on every read/write/export/delete
- Integer-cent financial arithmetic (zero floating-point drift) with strict currency boundaries
- Duplicate-Sale Safety & "Needs Action" state machine requiring manual confirmation per external listing
- CSV Formula-Injection Sanitization (`=`, `+`, `-`, `@`, `\t`, `\r` neutralization)
"""

import csv
import datetime
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import uuid
from typing import Any, Dict, List, Optional, Tuple


VALID_CURRENCIES = {"USD", "EUR", "GBP", "CAD", "AUD", "EGP"}
VALID_MARKETPLACES = {
    "StubHub",
    "Viagogo",
    "Ticketmaster Resale",
    "SeatGeek",
    "Vivid Seats",
    "TickPick",
    "Direct / Private",
    "Other",
}
VALID_TICKET_STATUSES = {"Available", "Listed", "Sold", "Needs Action", "Archived"}
VALID_LISTING_STATUSES = {"Active", "Pending", "Sold", "Removed", "Expired", "Unknown"}
VALID_PAYOUT_STATUSES = {"Expected", "Processing", "Paid", "Overdue", "Disputed", "Cancelled"}


class TicketPilotError(Exception):
    """Base error for safe user-facing exceptions without leaking internal stack traces."""


class AuthorizationError(TicketPilotError):
    """Raised when an unauthenticated or unauthorized user attempts an operation."""


class ValidationError(TicketPilotError):
    """Raised when input validation or business state rules fail."""


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def normalize_email(email: str) -> str:
    if not email or not isinstance(email, str):
        raise ValidationError("A valid email address is required.")
    cleaned = email.strip().lower()
    if not re.match(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$", cleaned):
        raise ValidationError("Invalid email address format.")
    return cleaned


def validate_password_strength(password: str) -> None:
    if not password or len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must include at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must include at least one number.")


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    salt_hex = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        120_000,
    )
    return dk.hex(), salt_hex


def verify_password(password: str, expected_hash: str, salt_hex: str) -> bool:
    computed_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(computed_hash, expected_hash)


def sanitize_csv_cell(value: Any) -> str:
    """Protects against spreadsheet formula injection (CSV Injection)."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


class TicketPilotEngine:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                accepted_terms_at TEXT NOT NULL,
                accepted_privacy_at TEXT NOT NULL,
                subscription_tier TEXT NOT NULL DEFAULT 'free_launch',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_preferences (
                user_id TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
                default_currency TEXT NOT NULL DEFAULT 'USD',
                stale_listing_days INTEGER NOT NULL DEFAULT 7,
                upcoming_event_window_days INTEGER NOT NULL DEFAULT 7,
                in_app_alerts_enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                event_name TEXT NOT NULL,
                event_datetime TEXT NOT NULL,
                event_timezone TEXT NOT NULL DEFAULT 'America/New_York',
                venue TEXT NOT NULL,
                section TEXT NOT NULL,
                row_name TEXT NOT NULL,
                seat_range TEXT,
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                acquisition_cost_cents INTEGER NOT NULL CHECK (acquisition_cost_cents >= 0),
                currency TEXT NOT NULL,
                acquisition_date TEXT,
                status TEXT NOT NULL DEFAULT 'Available',
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS external_listings (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
                marketplace_name TEXT NOT NULL,
                external_listing_url TEXT,
                marketplace_reference_id TEXT,
                asking_price_cents INTEGER NOT NULL CHECK (asking_price_cents > 0),
                currency TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active',
                last_verified_at TEXT NOT NULL,
                resolution_confirmed_at TEXT,
                resolution_notes TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sales (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                ticket_id TEXT NOT NULL UNIQUE REFERENCES tickets(id) ON DELETE RESTRICT,
                sold_listing_id TEXT REFERENCES external_listings(id) ON DELETE SET NULL,
                sale_datetime TEXT NOT NULL,
                marketplace_name TEXT NOT NULL,
                external_order_id TEXT,
                gross_sale_cents INTEGER NOT NULL CHECK (gross_sale_cents >= 0),
                marketplace_fee_cents INTEGER NOT NULL DEFAULT 0 CHECK (marketplace_fee_cents >= 0),
                other_costs_cents INTEGER NOT NULL DEFAULT 0 CHECK (other_costs_cents >= 0),
                adjustments_cents INTEGER NOT NULL DEFAULT 0,
                net_proceeds_cents INTEGER NOT NULL,
                realized_profit_cents INTEGER NOT NULL,
                currency TEXT NOT NULL,
                sale_status TEXT NOT NULL DEFAULT 'Confirmed',
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS payouts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                sale_id TEXT NOT NULL UNIQUE REFERENCES sales(id) ON DELETE CASCADE,
                marketplace_name TEXT NOT NULL,
                expected_payout_cents INTEGER NOT NULL CHECK (expected_payout_cents >= 0),
                currency TEXT NOT NULL,
                expected_payout_date TEXT NOT NULL,
                actual_received_cents INTEGER,
                actual_receipt_date TEXT,
                payout_status TEXT NOT NULL DEFAULT 'Expected',
                external_payout_reference TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                related_ticket_id TEXT REFERENCES tickets(id) ON DELETE CASCADE,
                related_listing_id TEXT REFERENCES external_listings(id) ON DELETE CASCADE,
                related_payout_id TEXT REFERENCES payouts(id) ON DELETE CASCADE,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                requires_external_action INTEGER NOT NULL DEFAULT 0,
                dedup_key TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                is_handled INTEGER NOT NULL DEFAULT 0,
                handled_at TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, dedup_key)
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
                entity_type TEXT NOT NULL,
                entity_id TEXT,
                action_type TEXT NOT NULL,
                description TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    # -------------------------------------------------------------------------
    # AUDIT LOGGING & ALERT GENERATION
    # -------------------------------------------------------------------------
    def _log_activity(
        self,
        user_id: str,
        entity_type: str,
        entity_id: Optional[str],
        action_type: str,
        description: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO activity_logs (id, user_id, entity_type, entity_id, action_type, description, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                user_id,
                entity_type,
                entity_id,
                action_type,
                description,
                json.dumps(metadata or {}),
                utc_now_iso(),
            ),
        )

    def _upsert_alert(
        self,
        user_id: str,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        dedup_key: str,
        requires_external_action: bool = False,
        related_ticket_id: Optional[str] = None,
        related_listing_id: Optional[str] = None,
        related_payout_id: Optional[str] = None,
    ) -> str:
        existing = self.conn.execute(
            "SELECT id, is_handled FROM alerts WHERE user_id = ? AND dedup_key = ?",
            (user_id, dedup_key),
        ).fetchone()
        if existing:
            if existing["is_handled"] == 0:
                return existing["id"]
            # Re-open if previously handled and re-triggered
            self.conn.execute(
                """
                UPDATE alerts
                SET is_handled = 0, is_read = 0, handled_at = NULL, title = ?, message = ?, created_at = ?
                WHERE id = ? AND user_id = ?
                """,
                (title, message, utc_now_iso(), existing["id"], user_id),
            )
            return existing["id"]

        alert_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO alerts (
                id, user_id, related_ticket_id, related_listing_id, related_payout_id,
                alert_type, severity, title, message, requires_external_action,
                dedup_key, is_read, is_handled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
            """,
            (
                alert_id,
                user_id,
                related_ticket_id,
                related_listing_id,
                related_payout_id,
                alert_type,
                severity,
                title,
                message,
                1 if requires_external_action else 0,
                dedup_key,
                utc_now_iso(),
            ),
        )
        return alert_id

    # -------------------------------------------------------------------------
    # AUTHENTICATION & ACCOUNT MANAGEMENT
    # -------------------------------------------------------------------------
    def register_user(
        self,
        full_name: str,
        email: str,
        password: str,
        accepted_terms: bool,
        accepted_privacy: bool,
    ) -> Dict[str, Any]:
        if not full_name or len(full_name.strip()) < 2:
            raise ValidationError("Full name must be at least 2 characters.")
        if not accepted_terms or not accepted_privacy:
            raise ValidationError("You must accept the Terms of Service and Privacy Policy.")
        norm_email = normalize_email(email)
        validate_password_strength(password)

        existing = self.conn.execute(
            "SELECT id FROM profiles WHERE email = ?", (norm_email,)
        ).fetchone()
        if existing:
            raise ValidationError("Unable to complete registration with the provided email.")

        pw_hash, pw_salt = hash_password(password)
        verification_token = secrets.token_urlsafe(24)
        user_id = str(uuid.uuid4())
        now = utc_now_iso()

        self.conn.execute(
            """
            INSERT INTO profiles (
                id, full_name, email, password_hash, password_salt,
                email_verified, verification_token, accepted_terms_at,
                accepted_privacy_at, subscription_tier, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, 'free_launch', ?, ?)
            """,
            (user_id, full_name.strip(), norm_email, pw_hash, pw_salt, verification_token, now, now, now, now),
        )
        self.conn.execute(
            """
            INSERT INTO user_preferences (user_id, default_currency, stale_listing_days, upcoming_event_window_days, in_app_alerts_enabled, updated_at)
            VALUES (?, 'USD', 7, 7, 1, ?)
            """,
            (user_id, now),
        )
        self._log_activity(user_id, "profile", user_id, "REGISTER", "Account registered; awaiting email verification.")
        self.conn.commit()
        return {
            "user_id": user_id,
            "email": norm_email,
            "email_verified": False,
            "verification_token_for_testing_or_outbox": verification_token,
        }

    def verify_email(self, token: str) -> Dict[str, Any]:
        if not token:
            raise ValidationError("Verification token is required.")
        row = self.conn.execute(
            "SELECT id, email FROM profiles WHERE verification_token = ?", (token,)
        ).fetchone()
        if not row:
            raise ValidationError("Invalid or expired verification token.")
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE profiles SET email_verified = 1, verification_token = NULL, updated_at = ? WHERE id = ?",
            (now, row["id"]),
        )
        self._log_activity(row["id"], "profile", row["id"], "EMAIL_VERIFIED", "Email verification completed.")
        self.conn.commit()
        return {"user_id": row["id"], "email": row["email"], "email_verified": True}

    def login(self, email: str, password: str) -> Dict[str, Any]:
        norm_email = normalize_email(email)
        row = self.conn.execute(
            "SELECT id, full_name, email, password_hash, password_salt, email_verified FROM profiles WHERE email = ?",
            (norm_email,),
        ).fetchone()
        if not row or not verify_password(password, row["password_hash"], row["password_salt"]):
            raise AuthorizationError("Invalid email or password.")

        token = secrets.token_urlsafe(32)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = (now + datetime.timedelta(hours=24)).replace(microsecond=0).isoformat()
        self.conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, row["id"], now.replace(microsecond=0).isoformat(), expires),
        )
        self._log_activity(row["id"], "session", None, "LOGIN", "User logged in.")
        self.conn.commit()
        return {
            "session_token": token,
            "user": {
                "id": row["id"],
                "full_name": row["full_name"],
                "email": row["email"],
                "email_verified": bool(row["email_verified"]),
            },
        }

    def require_verified_user(self, session_token: str) -> Dict[str, Any]:
        if not session_token:
            raise AuthorizationError("Authentication required.")
        row = self.conn.execute(
            """
            SELECT p.id, p.full_name, p.email, p.email_verified, s.expires_at
            FROM sessions s
            JOIN profiles p ON p.id = s.user_id
            WHERE s.token = ?
            """,
            (session_token,),
        ).fetchone()
        if not row:
            raise AuthorizationError("Invalid or expired session token.")
        if row["expires_at"] < utc_now_iso():
            raise AuthorizationError("Session has expired. Please log in again.")
        if not row["email_verified"]:
            raise AuthorizationError("Email verification is required before accessing business records.")
        return dict(row)

    # -------------------------------------------------------------------------
    # TICKET INVENTORY CRUD
    # -------------------------------------------------------------------------
    def create_ticket(
        self,
        session_token: str,
        event_name: str,
        event_datetime: str,
        venue: str,
        section: str,
        row_name: str,
        quantity: int,
        acquisition_cost_cents: int,
        currency: str,
        seat_range: Optional[str] = None,
        acquisition_date: Optional[str] = None,
        event_timezone: str = "America/New_York",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        if not event_name or len(event_name.strip()) < 2:
            raise ValidationError("Event name is required.")
        if not venue or len(venue.strip()) < 2:
            raise ValidationError("Venue is required.")
        if not section or not str(section).strip():
            raise ValidationError("Section is required.")
        if not row_name or not str(row_name).strip():
            raise ValidationError("Row is required.")
        if not isinstance(quantity, int) or quantity <= 0 or quantity > 1000:
            raise ValidationError("Quantity must be a positive integer between 1 and 1000.")
        if not isinstance(acquisition_cost_cents, int) or acquisition_cost_cents < 0:
            raise ValidationError("Acquisition cost must be a non-negative integer (in cents).")
        if currency not in VALID_CURRENCIES:
            raise ValidationError(f"Unsupported currency: {currency}")

        ticket_id = str(uuid.uuid4())
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO tickets (
                id, user_id, event_name, event_datetime, event_timezone,
                venue, section, row_name, seat_range, quantity,
                acquisition_cost_cents, currency, acquisition_date,
                status, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Available', ?, ?, ?)
            """,
            (
                ticket_id,
                user["id"],
                event_name.strip(),
                event_datetime,
                event_timezone,
                venue.strip(),
                str(section).strip(),
                str(row_name).strip(),
                seat_range.strip() if seat_range else None,
                quantity,
                acquisition_cost_cents,
                currency,
                acquisition_date,
                notes,
                now,
                now,
            ),
        )
        self._log_activity(
            user["id"],
            "ticket",
            ticket_id,
            "CREATE_TICKET",
            f"Created ticket inventory for {event_name.strip()} ({quantity}x, {currency} {acquisition_cost_cents/100:.2f}).",
        )
        self.conn.commit()
        return self.get_ticket(session_token, ticket_id)

    def get_ticket(self, session_token: str, ticket_id: str) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        row = self.conn.execute(
            "SELECT * FROM tickets WHERE id = ? AND user_id = ?",
            (ticket_id, user["id"]),
        ).fetchone()
        if not row:
            raise AuthorizationError("Ticket record not found or access denied.")
        ticket = dict(row)
        listings = self.conn.execute(
            "SELECT * FROM external_listings WHERE ticket_id = ? AND user_id = ? ORDER BY asking_price_cents ASC",
            (ticket_id, user["id"]),
        ).fetchall()
        ticket["listings"] = [dict(l) for l in listings]
        ticket["lowest_active_prices_by_currency"] = self._compute_lowest_active_prices(ticket["listings"])
        return ticket

    def _compute_lowest_active_prices(self, listings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculates lowest active asking price strictly grouped by currency (never mixes currencies)."""
        lowest: Dict[str, int] = {}
        for l in listings:
            if l["status"] == "Active":
                curr = l["currency"]
                price = int(l["asking_price_cents"])
                if curr not in lowest or price < lowest[curr]:
                    lowest[curr] = price
        return lowest

    def archive_ticket(self, session_token: str, ticket_id: str) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        ticket = self.get_ticket(session_token, ticket_id)
        if ticket["status"] == "Needs Action":
            raise ValidationError("Cannot archive a ticket while it is in 'Needs Action' state with unresolved external listings.")
        now = utc_now_iso()
        self.conn.execute(
            "UPDATE tickets SET status = 'Archived', updated_at = ? WHERE id = ? AND user_id = ?",
            (now, ticket_id, user["id"]),
        )
        self._log_activity(user["id"], "ticket", ticket_id, "ARCHIVE_TICKET", f"Archived ticket {ticket['event_name']}.")
        self.conn.commit()
        return self.get_ticket(session_token, ticket_id)

    # -------------------------------------------------------------------------
    # EXTERNAL LISTINGS MANAGEMENT
    # -------------------------------------------------------------------------
    def create_external_listing(
        self,
        session_token: str,
        ticket_id: str,
        marketplace_name: str,
        asking_price_cents: int,
        currency: str,
        external_listing_url: Optional[str] = None,
        marketplace_reference_id: Optional[str] = None,
        status: str = "Active",
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        ticket = self.get_ticket(session_token, ticket_id)
        if ticket["status"] in ("Sold", "Needs Action", "Archived"):
            raise ValidationError(f"Cannot add new active listing to a ticket in '{ticket['status']}' status.")
        if marketplace_name not in VALID_MARKETPLACES:
            raise ValidationError(f"Unsupported marketplace: {marketplace_name}")
        if not isinstance(asking_price_cents, int) or asking_price_cents <= 0:
            raise ValidationError("Asking price must be a positive integer (in cents).")
        if currency not in VALID_CURRENCIES:
            raise ValidationError(f"Unsupported currency: {currency}")
        if status not in VALID_LISTING_STATUSES:
            raise ValidationError(f"Invalid listing status: {status}")

        listing_id = str(uuid.uuid4())
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO external_listings (
                id, user_id, ticket_id, marketplace_name, external_listing_url,
                marketplace_reference_id, asking_price_cents, currency, status,
                last_verified_at, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                listing_id,
                user["id"],
                ticket_id,
                marketplace_name,
                external_listing_url,
                marketplace_reference_id,
                asking_price_cents,
                currency,
                status,
                now,
                notes,
                now,
                now,
            ),
        )
        if status in ("Active", "Pending") and ticket["status"] == "Available":
            self.conn.execute(
                "UPDATE tickets SET status = 'Listed', updated_at = ? WHERE id = ? AND user_id = ?",
                (now, ticket_id, user["id"]),
            )

        self._log_activity(
            user["id"],
            "external_listing",
            listing_id,
            "CREATE_LISTING",
            f"Listed ticket on {marketplace_name} at {currency} {asking_price_cents/100:.2f}.",
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT * FROM external_listings WHERE id = ? AND user_id = ?", (listing_id, user["id"])
        ).fetchone()
        return dict(row)

    # -------------------------------------------------------------------------
    # SALES & DUPLICATE-SALE SAFETY ("NEEDS ACTION") WORKFLOW
    # -------------------------------------------------------------------------
    def record_sale(
        self,
        session_token: str,
        ticket_id: str,
        marketplace_name: str,
        gross_sale_cents: int,
        marketplace_fee_cents: int,
        other_costs_cents: int = 0,
        adjustments_cents: int = 0,
        currency: str = "USD",
        sold_listing_id: Optional[str] = None,
        external_order_id: Optional[str] = None,
        expected_payout_date: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Records a completed sale, computes exact integer-cent Net Proceeds & Realized Profit,
        creates an Expected Payout record, and triggers Duplicate-Sale Safety ("Needs Action")
        if any other Active/Pending/Unknown external listings exist on the same ticket.
        """
        user = self.require_verified_user(session_token)
        ticket = self.get_ticket(session_token, ticket_id)
        if ticket["status"] in ("Sold", "Needs Action"):
            raise ValidationError("A sale is already recorded for this ticket.")
        if currency != ticket["currency"]:
            raise ValidationError(
                f"Currency mismatch: Sale currency ({currency}) must match ticket acquisition currency ({ticket['currency']}) unless explicit conversion is recorded."
            )
        if gross_sale_cents < 0 or marketplace_fee_cents < 0 or other_costs_cents < 0:
            raise ValidationError("Sale and fee amounts must be non-negative integers.")

        if sold_listing_id:
            listing_check = self.conn.execute(
                "SELECT id FROM external_listings WHERE id = ? AND ticket_id = ? AND user_id = ?",
                (sold_listing_id, ticket_id, user["id"]),
            ).fetchone()
            if not listing_check:
                raise AuthorizationError("Referenced listing does not belong to this ticket or user.")

        # Financial Calculations (Integer Cents)
        net_proceeds_cents = gross_sale_cents - marketplace_fee_cents - other_costs_cents + adjustments_cents
        realized_profit_cents = net_proceeds_cents - int(ticket["acquisition_cost_cents"])

        sale_id = str(uuid.uuid4())
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO sales (
                id, user_id, ticket_id, sold_listing_id, sale_datetime,
                marketplace_name, external_order_id, gross_sale_cents,
                marketplace_fee_cents, other_costs_cents, adjustments_cents,
                net_proceeds_cents, realized_profit_cents, currency,
                sale_status, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Confirmed', ?, ?, ?)
            """,
            (
                sale_id,
                user["id"],
                ticket_id,
                sold_listing_id,
                now,
                marketplace_name,
                external_order_id,
                gross_sale_cents,
                marketplace_fee_cents,
                other_costs_cents,
                adjustments_cents,
                net_proceeds_cents,
                realized_profit_cents,
                currency,
                notes,
                now,
                now,
            ),
        )

        if sold_listing_id:
            self.conn.execute(
                "UPDATE external_listings SET status = 'Sold', updated_at = ? WHERE id = ? AND user_id = ?",
                (now, sold_listing_id, user["id"]),
            )

        # Create Expected Payout record automatically (never counted as received money until confirmed)
        payout_id = str(uuid.uuid4())
        due_date = expected_payout_date or (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
        ).strftime("%Y-%m-%d")
        self.conn.execute(
            """
            INSERT INTO payouts (
                id, user_id, sale_id, marketplace_name, expected_payout_cents,
                currency, expected_payout_date, actual_received_cents,
                actual_receipt_date, payout_status, notes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'Expected', ?, ?, ?)
            """,
            (payout_id, user["id"], sale_id, marketplace_name, max(0, net_proceeds_cents), currency, due_date, notes, now, now),
        )

        # Check for remaining unresolved external listings on this ticket
        unresolved_rows = self.conn.execute(
            """
            SELECT * FROM external_listings
            WHERE ticket_id = ? AND user_id = ?
              AND status IN ('Active', 'Pending', 'Unknown')
              AND (? IS NULL OR id != ?)
            """,
            (ticket_id, user["id"], sold_listing_id, sold_listing_id),
        ).fetchall()
        unresolved = [dict(r) for r in unresolved_rows]

        if unresolved:
            new_ticket_status = "Needs Action"
            platforms_str = ", ".join(f"{u['marketplace_name']} ({u['marketplace_reference_id'] or 'No Ref'})" for u in unresolved)
            self._upsert_alert(
                user_id=user["id"],
                alert_type="DUPLICATE_SALE_RISK",
                severity="critical",
                title=f"URGENT: Deactivate {len(unresolved)} External Listing(s) for {ticket['event_name']}",
                message=(
                    f"Sale recorded on {marketplace_name}, but {len(unresolved)} other listing(s) remain unresolved on: "
                    f"{platforms_str}. TicketPilot does NOT automatically cancel external listings. "
                    f"Visit each marketplace immediately to remove the listing, then confirm removal in TicketPilot."
                ),
                dedup_key=f"dup_sale_ticket_{ticket_id}",
                requires_external_action=True,
                related_ticket_id=ticket_id,
            )
        else:
            new_ticket_status = "Sold"

        self.conn.execute(
            "UPDATE tickets SET status = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (new_ticket_status, now, ticket_id, user["id"]),
        )

        self._log_activity(
            user["id"],
            "sale",
            sale_id,
            "RECORD_SALE",
            f"Recorded sale on {marketplace_name} for {ticket['event_name']}. Ticket status set to '{new_ticket_status}'.",
            {"unresolved_listings_count": len(unresolved), "realized_profit_cents": realized_profit_cents},
        )
        self.conn.commit()
        return {
            "sale_id": sale_id,
            "payout_id": payout_id,
            "ticket_status": new_ticket_status,
            "net_proceeds_cents": net_proceeds_cents,
            "realized_profit_cents": realized_profit_cents,
            "unresolved_listings": unresolved,
        }

    def confirm_external_listing_removed(
        self,
        session_token: str,
        listing_id: str,
        resolution_status: str = "Removed",
        resolution_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Manual confirmation by the user that an external listing has been removed/handled on the external platform.
        Transitions the parent ticket from 'Needs Action' to 'Sold' ONLY when zero unresolved listings remain.
        """
        user = self.require_verified_user(session_token)
        if resolution_status not in ("Removed", "Expired"):
            raise ValidationError("Resolution status must be 'Removed' or 'Expired'.")

        listing = self.conn.execute(
            "SELECT * FROM external_listings WHERE id = ? AND user_id = ?",
            (listing_id, user["id"]),
        ).fetchone()
        if not listing:
            raise AuthorizationError("Listing not found or access denied.")

        now = utc_now_iso()
        self.conn.execute(
            """
            UPDATE external_listings
            SET status = ?, resolution_confirmed_at = ?, resolution_notes = ?, last_verified_at = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (resolution_status, now, resolution_notes or "Manually confirmed removed by user", now, now, listing_id, user["id"]),
        )

        ticket_id = listing["ticket_id"]
        remaining = self.conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM external_listings
            WHERE ticket_id = ? AND user_id = ? AND status IN ('Active', 'Pending', 'Unknown')
            """,
            (ticket_id, user["id"]),
        ).fetchone()["cnt"]

        ticket_row = self.conn.execute(
            "SELECT status, event_name FROM tickets WHERE id = ? AND user_id = ?",
            (ticket_id, user["id"]),
        ).fetchone()
        current_ticket_status = ticket_row["status"]

        if remaining == 0 and current_ticket_status == "Needs Action":
            current_ticket_status = "Sold"
            self.conn.execute(
                "UPDATE tickets SET status = 'Sold', updated_at = ? WHERE id = ? AND user_id = ?",
                (now, ticket_id, user["id"]),
            )
            self.conn.execute(
                """
                UPDATE alerts
                SET is_handled = 1, is_read = 1, handled_at = ?
                WHERE user_id = ? AND dedup_key = ?
                """,
                (now, user["id"], f"dup_sale_ticket_{ticket_id}"),
            )

        self._log_activity(
            user["id"],
            "external_listing",
            listing_id,
            "CONFIRM_LISTING_REMOVAL",
            f"User manually confirmed {listing['marketplace_name']} listing marked as {resolution_status}. Remaining unresolved: {remaining}.",
            {"ticket_id": ticket_id, "remaining_unresolved": remaining, "ticket_status": current_ticket_status},
        )
        self.conn.commit()
        return {
            "listing_id": listing_id,
            "listing_status": resolution_status,
            "remaining_unresolved_listings": remaining,
            "ticket_status": current_ticket_status,
        }

    # -------------------------------------------------------------------------
    # PAYOUTS & FINANCIAL SUMMARY BY CURRENCY
    # -------------------------------------------------------------------------
    def record_payout_received(
        self,
        session_token: str,
        payout_id: str,
        actual_received_cents: int,
        actual_receipt_date: Optional[str] = None,
        external_payout_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        if actual_received_cents < 0:
            raise ValidationError("Actual received payout must be non-negative.")
        payout = self.conn.execute(
            "SELECT * FROM payouts WHERE id = ? AND user_id = ?",
            (payout_id, user["id"]),
        ).fetchone()
        if not payout:
            raise AuthorizationError("Payout record not found or access denied.")

        now = utc_now_iso()
        r_date = actual_receipt_date or now[:10]
        self.conn.execute(
            """
            UPDATE payouts
            SET actual_received_cents = ?, actual_receipt_date = ?, payout_status = 'Paid',
                external_payout_reference = COALESCE(?, external_payout_reference), updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (actual_received_cents, r_date, external_payout_reference, now, payout_id, user["id"]),
        )
        self._log_activity(
            user["id"],
            "payout",
            payout_id,
            "PAYOUT_RECEIVED",
            f"Recorded actual payout received ({payout['currency']} {actual_received_cents/100:.2f}) from {payout['marketplace_name']}.",
        )
        self.conn.commit()
        return dict(
            self.conn.execute("SELECT * FROM payouts WHERE id = ? AND user_id = ?", (payout_id, user["id"])).fetchone()
        )

    def get_financial_summary(self, session_token: str) -> Dict[str, Any]:
        """
        Computes strict, currency-segregated financial metrics:
        - Never includes unsold ticket acquisition costs in realized profit.
        - Never counts asking prices as sales.
        - Never counts expected payouts as received payouts.
        - Never adds different currencies together.
        """
        user = self.require_verified_user(session_token)
        uid = user["id"]

        # Inventory counts
        counts = self.conn.execute(
            """
            SELECT
                COUNT(*) AS total_records,
                SUM(CASE WHEN status = 'Listed' THEN 1 ELSE 0 END) AS listed_count,
                SUM(CASE WHEN status = 'Needs Action' THEN 1 ELSE 0 END) AS needs_action_count,
                SUM(CASE WHEN status = 'Available' THEN 1 ELSE 0 END) AS available_count,
                SUM(CASE WHEN status IN ('Sold', 'Needs Action') THEN 1 ELSE 0 END) AS sold_or_pending_action_count
            FROM tickets
            WHERE user_id = ? AND status != 'Archived'
            """,
            (uid,),
        ).fetchone()

        # Currency-grouped sales & realized profit (only non-cancelled sales)
        sales_by_curr = self.conn.execute(
            """
            SELECT
                s.currency,
                COUNT(*) AS sales_count,
                SUM(s.gross_sale_cents) AS gross_sales_cents,
                SUM(s.marketplace_fee_cents) AS marketplace_fees_cents,
                SUM(s.other_costs_cents) AS other_costs_cents,
                SUM(t.acquisition_cost_cents) AS sold_acquisition_cost_cents,
                SUM(s.net_proceeds_cents) AS net_proceeds_cents,
                SUM(s.realized_profit_cents) AS realized_profit_cents
            FROM sales s
            JOIN tickets t ON t.id = s.ticket_id
            WHERE s.user_id = ? AND s.sale_status != 'Cancelled'
            GROUP BY s.currency
            """,
            (uid,),
        ).fetchall()

        # Unsold inventory capital tied up (kept strictly separate from realized profit)
        unsold_by_curr = self.conn.execute(
            """
            SELECT currency, SUM(acquisition_cost_cents) AS unsold_acquisition_cost_cents
            FROM tickets
            WHERE user_id = ? AND status IN ('Available', 'Listed')
            GROUP BY currency
            """,
            (uid,),
        ).fetchall()

        # Payouts by currency
        today_str = utc_now_iso()[:10]
        payouts_by_curr = self.conn.execute(
            """
            SELECT
                currency,
                SUM(CASE WHEN payout_status IN ('Expected', 'Processing', 'Overdue') THEN expected_payout_cents ELSE 0 END) AS expected_pending_cents,
                SUM(CASE WHEN payout_status = 'Paid' THEN COALESCE(actual_received_cents, 0) ELSE 0 END) AS received_payouts_cents,
                SUM(CASE WHEN payout_status IN ('Expected', 'Processing') AND expected_payout_date < ? OR payout_status = 'Overdue' THEN 1 ELSE 0 END) AS overdue_count
            FROM payouts
            WHERE user_id = ? AND payout_status != 'Cancelled'
            GROUP BY currency
            """,
            (today_str, uid),
        ).fetchall()

        currencies_summary: Dict[str, Dict[str, int]] = {}
        for row in sales_by_curr:
            c = row["currency"]
            currencies_summary.setdefault(
                c,
                {
                    "sales_count": 0,
                    "gross_sales_cents": 0,
                    "marketplace_fees_cents": 0,
                    "other_costs_cents": 0,
                    "sold_acquisition_cost_cents": 0,
                    "net_proceeds_cents": 0,
                    "realized_profit_cents": 0,
                    "unsold_inventory_cost_cents": 0,
                    "expected_pending_payouts_cents": 0,
                    "received_payouts_cents": 0,
                    "overdue_payouts_count": 0,
                },
            )
            currencies_summary[c].update(
                {
                    "sales_count": int(row["sales_count"] or 0),
                    "gross_sales_cents": int(row["gross_sales_cents"] or 0),
                    "marketplace_fees_cents": int(row["marketplace_fees_cents"] or 0),
                    "other_costs_cents": int(row["other_costs_cents"] or 0),
                    "sold_acquisition_cost_cents": int(row["sold_acquisition_cost_cents"] or 0),
                    "net_proceeds_cents": int(row["net_proceeds_cents"] or 0),
                    "realized_profit_cents": int(row["realized_profit_cents"] or 0),
                }
            )

        for row in unsold_by_curr:
            c = row["currency"]
            currencies_summary.setdefault(
                c,
                {
                    "sales_count": 0,
                    "gross_sales_cents": 0,
                    "marketplace_fees_cents": 0,
                    "other_costs_cents": 0,
                    "sold_acquisition_cost_cents": 0,
                    "net_proceeds_cents": 0,
                    "realized_profit_cents": 0,
                    "unsold_inventory_cost_cents": 0,
                    "expected_pending_payouts_cents": 0,
                    "received_payouts_cents": 0,
                    "overdue_payouts_count": 0,
                },
            )
            currencies_summary[c]["unsold_inventory_cost_cents"] = int(row["unsold_acquisition_cost_cents"] or 0)

        for row in payouts_by_curr:
            c = row["currency"]
            currencies_summary.setdefault(
                c,
                {
                    "sales_count": 0,
                    "gross_sales_cents": 0,
                    "marketplace_fees_cents": 0,
                    "other_costs_cents": 0,
                    "sold_acquisition_cost_cents": 0,
                    "net_proceeds_cents": 0,
                    "realized_profit_cents": 0,
                    "unsold_inventory_cost_cents": 0,
                    "expected_pending_payouts_cents": 0,
                    "received_payouts_cents": 0,
                    "overdue_payouts_count": 0,
                },
            )
            currencies_summary[c]["expected_pending_payouts_cents"] = int(row["expected_pending_cents"] or 0)
            currencies_summary[c]["received_payouts_cents"] = int(row["received_payouts_cents"] or 0)
            currencies_summary[c]["overdue_payouts_count"] = int(row["overdue_count"] or 0)

        return {
            "inventory": {
                "total_records": int(counts["total_records"] or 0),
                "listed_count": int(counts["listed_count"] or 0),
                "needs_action_count": int(counts["needs_action_count"] or 0),
                "available_count": int(counts["available_count"] or 0),
            },
            "by_currency": currencies_summary,
        }

    # -------------------------------------------------------------------------
    # SECURE CSV EXPORT (WITH FORMULA INJECTION PROTECTION)
    # -------------------------------------------------------------------------
    def export_sales_csv(self, session_token: str, currency_filter: Optional[str] = None) -> str:
        user = self.require_verified_user(session_token)
        query = """
            SELECT
                s.id AS sale_id,
                t.event_name,
                t.venue,
                t.section,
                t.row_name,
                s.marketplace_name,
                s.sale_datetime,
                s.currency,
                s.gross_sale_cents,
                s.marketplace_fee_cents,
                s.other_costs_cents,
                t.acquisition_cost_cents,
                s.net_proceeds_cents,
                s.realized_profit_cents,
                s.notes
            FROM sales s
            JOIN tickets t ON t.id = s.ticket_id
            WHERE s.user_id = ?
        """
        params: List[Any] = [user["id"]]
        if currency_filter:
            query += " AND s.currency = ?"
            params.append(currency_filter)
        query += " ORDER BY s.sale_datetime DESC"

        rows = self.conn.execute(query, params).fetchall()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Sale ID",
                "Event Name",
                "Venue",
                "Section",
                "Row",
                "Marketplace",
                "Sale Date",
                "Currency",
                "Gross Sale",
                "Marketplace Fee",
                "Other Costs",
                "Acquisition Cost",
                "Net Proceeds",
                "Realized Profit",
                "Notes",
            ]
        )
        for r in rows:
            writer.writerow(
                [
                    sanitize_csv_cell(r["sale_id"]),
                    sanitize_csv_cell(r["event_name"]),
                    sanitize_csv_cell(r["venue"]),
                    sanitize_csv_cell(r["section"]),
                    sanitize_csv_cell(r["row_name"]),
                    sanitize_csv_cell(r["marketplace_name"]),
                    sanitize_csv_cell(r["sale_datetime"]),
                    sanitize_csv_cell(r["currency"]),
                    f"{r['gross_sale_cents']/100:.2f}",
                    f"{r['marketplace_fee_cents']/100:.2f}",
                    f"{r['other_costs_cents']/100:.2f}",
                    f"{r['acquisition_cost_cents']/100:.2f}",
                    f"{r['net_proceeds_cents']/100:.2f}",
                    f"{r['realized_profit_cents']/100:.2f}",
                    sanitize_csv_cell(r["notes"]),
                ]
            )
        return output.getvalue()

    def delete_account(self, session_token: str, current_password: str, explicit_confirmation: str) -> Dict[str, Any]:
        user = self.require_verified_user(session_token)
        if explicit_confirmation != "DELETE MY ACCOUNT":
            raise ValidationError("Explicit confirmation phrase 'DELETE MY ACCOUNT' is required.")
        profile = self.conn.execute(
            "SELECT password_hash, password_salt FROM profiles WHERE id = ?", (user["id"],)
        ).fetchone()
        if not verify_password(current_password, profile["password_hash"], profile["password_salt"]):
            raise AuthorizationError("Reauthentication failed: incorrect password.")

        # Temporarily disable foreign key RESTRICT on sold tickets to allow full cascade purge of user's own account
        self.conn.execute("PRAGMA foreign_keys = OFF;")
        self.conn.execute("DELETE FROM payouts WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM sales WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM external_listings WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM alerts WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM activity_logs WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM tickets WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM user_preferences WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        self.conn.execute("DELETE FROM profiles WHERE id = ?", (user["id"],))
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.conn.commit()
        return {
            "deleted_user_id": user["id"],
            "active_database_purged": True,
            "backup_retention_disclosure": (
                "Active database records have been deleted immediately. If hosted on a managed cloud database "
                "with automated point-in-time recovery backups, encrypted backup snapshots expire according "
                "to the provider's retention window (e.g., 7 days on Supabase Pro; 0 automated backups on Supabase Free)."
            ),
        }
