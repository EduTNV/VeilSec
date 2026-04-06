"""initial schema

Revision ID: 0001
Revises:
Create Date: 2024-01-01 00:00:00
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE plan_enum AS ENUM ('FREE', 'PRO', 'ENTERPRISE')")
    op.execute("CREATE TYPE scan_type_enum AS ENUM ('SAST', 'DAST')")
    op.execute("CREATE TYPE scan_status_enum AS ENUM ('PENDING', 'RUNNING', 'DONE', 'FAILED', 'BLOCKED')")
    op.execute("CREATE TYPE severity_enum AS ENUM ('low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE finding_category_enum AS ENUM ('PII_LEAK', 'BROKEN_AUTH', 'INJECTION', 'SENSITIVE_EXPOSURE', 'MISSING_CONSENT', 'MISSING_RETENTION', 'MISSING_DELETION', 'PROMPT_INJECTION')")
    op.execute("CREATE TYPE language_enum AS ENUM ('python', 'javascript')")

    op.create_table("clients",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("api_key_hash", sa.String(64), nullable=True),
        sa.Column("api_key_id", sa.String(32), nullable=True),
        sa.Column("api_key_revoked", sa.Boolean, default=False, nullable=False),
        sa.Column("plan", sa.Enum("FREE", "PRO", "ENTERPRISE", name="plan_enum", create_type=False), default="FREE", nullable=False),
        sa.Column("lgpd_consent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lgpd_consent_version", sa.String(10), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_clients_email", "clients", ["email"], unique=True)
    op.create_index("ix_clients_api_key_hash", "clients", ["api_key_hash"], unique=True)

    op.create_table("projects",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("client_id", UUID(as_uuid=True), sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("ownership_verified", sa.Boolean, default=False, nullable=False),
        sa.Column("ownership_proof_id", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_projects_client_id", "projects", ["client_id"])

    op.create_table("ownership_proofs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("token", sa.String(64), nullable=False, unique=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("methods_verified", JSONB, default=list, nullable=False),
        sa.Column("is_valid", sa.Boolean, default=False, nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_ownership_proofs_client_id", "ownership_proofs", ["client_id"])

    op.create_table("scans",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_id", UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.Enum("SAST", "DAST", name="scan_type_enum", create_type=False), nullable=False),
        sa.Column("status", sa.Enum("PENDING", "RUNNING", "DONE", "FAILED", "BLOCKED", name="scan_status_enum", create_type=False), default="PENDING", nullable=False),
        sa.Column("language", sa.Enum("python", "javascript", name="language_enum", create_type=False), nullable=True),
        sa.Column("input_ref", sa.String(512), nullable=False),
        sa.Column("result_ref", sa.String(512), nullable=True),
        sa.Column("ownership_proof_id", UUID(as_uuid=True), nullable=True),
        sa.Column("initiated_by", UUID(as_uuid=True), nullable=False),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_client_id_status", "scans", ["client_id", "status"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])

    op.create_table("findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("severity", sa.Enum("low", "medium", "high", "critical", name="severity_enum", create_type=False), nullable=False),
        sa.Column("category", sa.Enum("PII_LEAK", "BROKEN_AUTH", "INJECTION", "SENSITIVE_EXPOSURE", "MISSING_CONSENT", "MISSING_RETENTION", "MISSING_DELETION", "PROMPT_INJECTION", name="finding_category_enum", create_type=False), nullable=False),
        sa.Column("lgpd_article", sa.String(20), nullable=True),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("remediation", sa.Text, nullable=False),
        sa.Column("raw_evidence_ref", sa.String(512), nullable=False),
        sa.Column("location", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    # Audit log — append-only enforced via trigger
    op.create_table("audit_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("event", sa.String(100), nullable=False),
        sa.Column("context", JSONB, nullable=False, default=dict),
        sa.Column("integrity_hash", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
    )
    op.create_index("ix_audit_log_event_timestamp", "audit_log", ["event", "timestamp"])

    # Trigger que impede UPDATE/DELETE no audit_log
    op.execute("""
        CREATE OR REPLACE FUNCTION prevent_audit_modification()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Operação % na tabela audit_log é proibida. O audit log é imutável.', TG_OP;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER audit_log_immutable
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_immutable ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_modification()")
    op.drop_table("audit_log")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("ownership_proofs")
    op.drop_table("projects")
    op.drop_table("clients")
    op.execute("DROP TYPE IF EXISTS language_enum")
    op.execute("DROP TYPE IF EXISTS finding_category_enum")
    op.execute("DROP TYPE IF EXISTS severity_enum")
    op.execute("DROP TYPE IF EXISTS scan_status_enum")
    op.execute("DROP TYPE IF EXISTS scan_type_enum")
    op.execute("DROP TYPE IF EXISTS plan_enum")
