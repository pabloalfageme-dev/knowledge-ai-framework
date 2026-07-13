"""Auth & multi-tenancy foundation: tables, indexes, DB roles, RLS policies

Revision ID: 001
Revises:
Create Date: 2026-07-04
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── DB roles ─────────────────────────────────────────────────────────────
    # kn_app: application role, subject to RLS
    # kn_admin: operator role, bypasses RLS for super-admin cross-org queries
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kn_app') THEN
                CREATE ROLE kn_app NOLOGIN;
            END IF;
        END
        $$;
    """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kn_admin') THEN
                CREATE ROLE kn_admin NOLOGIN BYPASSRLS;
            END IF;
        END
        $$;
    """)

    # Allow kn_app sessions to escalate to kn_admin via SET LOCAL ROLE for
    # cross-org super-admin operations (FR-012 aggregates, org lifecycle).
    op.execute("GRANT kn_admin TO kn_app;")

    # ── Tables ───────────────────────────────────────────────────────────────
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("name", name="uq_organizations_name"),
    )

    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("credential_hash", sa.String(255), nullable=False),
        sa.Column("credential_type", sa.String(10), nullable=False, server_default="password"),
        sa.Column("role", sa.String(15), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="active"),
        sa.Column("failed_login_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("event_type", sa.String(20), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("family_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_hash"),
    )

    # ── Indexes ──────────────────────────────────────────────────────────────
    op.create_index("ix_organizations_status", "organizations", ["status"])
    op.create_index("ix_users_organization_id", "users", ["organization_id"])
    op.create_index("ix_users_org_status", "users", ["organization_id", "status"])
    op.create_index("ix_audit_log_org_occurred", "audit_log", ["organization_id", "occurred_at"])
    op.create_index("ix_audit_log_user_occurred", "audit_log", ["user_id", "occurred_at"])
    op.create_index("ix_refresh_tokens_family", "refresh_tokens", ["family_id"])
    op.create_index("ix_refresh_tokens_user_expires", "refresh_tokens", ["user_id", "expires_at"])

    # ── Grants ───────────────────────────────────────────────────────────────
    for table in ("organizations", "users", "audit_log", "refresh_tokens"):
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO kn_app;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO kn_admin;")

    # ── Row-Level Security ───────────────────────────────────────────────────
    # organizations: NOT RLS-restricted — super-admin must read freely.
    # users, audit_log, refresh_tokens: filtered by current_setting('app.current_org_id').
    # The application sets this via SET LOCAL before tenant-scoped queries.
    # Uses the safe form current_setting(..., true) which returns NULL (not an error)
    # when the variable is not set, so super-admin operations on kn_admin role work
    # without triggering the policy.

    for table in ("users", "audit_log", "refresh_tokens"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {table}
            AS PERMISSIVE
            FOR ALL
            TO kn_app
            USING (
                organization_id = current_setting('app.current_org_id', true)::uuid
            )
            WITH CHECK (
                organization_id = current_setting('app.current_org_id', true)::uuid
            );
        """)


def downgrade() -> None:
    for table in ("users", "audit_log", "refresh_tokens"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.drop_table("refresh_tokens")
    op.drop_table("audit_log")
    op.drop_table("users")
    op.drop_table("organizations")

    op.execute("DROP ROLE IF EXISTS kn_app;")
    op.execute("DROP ROLE IF EXISTS kn_admin;")