"""Initial database schema

Revision ID: 001
Revises: 
Create Date: 2026-04-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create sessions table
    op.create_table(
        'sessions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target', sa.String(length=255), nullable=False),
        sa.Column('start_time', sa.DateTime(), nullable=False),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('risk_level', sa.String(length=50), nullable=True),
        sa.Column('current_stage', sa.String(length=50), nullable=True),
        sa.Column('last_checkpoint', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create targets table
    op.create_table(
        'targets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('open_ports', sa.JSON(), nullable=True),
        sa.Column('tech_stack', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_targets_session_id'), 'targets', ['session_id'], unique=False)

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=True),
        sa.Column('vuln_name', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cve_id', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_session_id'), 'findings', ['session_id'], unique=False)
    op.create_index(op.f('ix_findings_target_id'), 'findings', ['target_id'], unique=False)

    # Create ai_reasoning_chains table
    op.create_table(
        'ai_reasoning_chains',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('stage', sa.Enum('RECON', 'ATTACK_SURFACE', 'EXPLOIT_PRIORITY', 'REMEDIATION', name='reasoningstage'), nullable=False),
        sa.Column('input_context', sa.Text(), nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('model_used', sa.String(length=100), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_reasoning_chains_session_id'), 'ai_reasoning_chains', ['session_id'], unique=False)

    # Create exploits table
    op.create_table(
        'exploits',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('payload', sa.Text(), nullable=True),
        sa.Column('result', sa.Text(), nullable=True),
        sa.Column('attempted_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_exploits_finding_id'), 'exploits', ['finding_id'], unique=False)

    # Create exports table
    op.create_table(
        'exports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('format', sa.String(length=20), nullable=False),
        sa.Column('filepath', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_exports_session_id'), 'exports', ['session_id'], unique=False)

    # Create checkpoints table
    op.create_table(
        'checkpoints',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('session_id', sa.Integer(), nullable=False),
        sa.Column('stage', sa.String(length=50), nullable=False),
        sa.Column('module_name', sa.String(length=100), nullable=True),
        sa.Column('state', sa.String(length=50), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_checkpoints_session_id'), 'checkpoints', ['session_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_checkpoints_session_id'), table_name='checkpoints')
    op.drop_table('checkpoints')
    op.drop_index(op.f('ix_exports_session_id'), table_name='exports')
    op.drop_table('exports')
    op.drop_index(op.f('ix_exploits_finding_id'), table_name='exploits')
    op.drop_table('exploits')
    op.drop_index(op.f('ix_ai_reasoning_chains_session_id'), table_name='ai_reasoning_chains')
    op.drop_table('ai_reasoning_chains')
    op.drop_index(op.f('ix_findings_target_id'), table_name='findings')
    op.drop_index(op.f('ix_findings_session_id'), table_name='findings')
    op.drop_table('findings')
    op.drop_index(op.f('ix_targets_session_id'), table_name='targets')
    op.drop_table('targets')
    op.drop_table('sessions')
