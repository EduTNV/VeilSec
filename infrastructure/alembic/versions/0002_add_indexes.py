"""add performance indexes

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-01 00:01:00
"""
from __future__ import annotations
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_scans_retention
        ON scans (created_at)
        WHERE input_ref != 'DELETED'
    """)
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_log_client_id
        ON audit_log ((context->>'client_id'))
    """)
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_scan_severity
        ON findings (scan_id, severity)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scans_retention")
    op.execute("DROP INDEX IF EXISTS ix_audit_log_client_id")
    op.execute("DROP INDEX IF EXISTS ix_findings_scan_severity")
