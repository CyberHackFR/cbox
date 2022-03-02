"""Create NetworkTypes and SystemTypes

Revision ID: b1685fc5f49c
Revises: 9a02836f6117
Create Date: 2020-10-21 10:01:06.180863

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from source.wizard.models import SystemType, NetworkType, ScanCategory
# revision identifiers, used by Alembic.
revision = 'b1685fc5f49c'
down_revision = '9a02836f6117'
branch_labels = None
depends_on = None


def upgrade():
    """Upgrade to migration."""
    op.bulk_insert(SystemType.__table__, [
        {'id': 1, 'name': 'Cbox'},
        {'id': 2, 'name': 'DNS-Server'},
        {'id': 3, 'name': 'Gateway'},
        {'id': 4, 'name': 'Firewall'},
        {'id': 5, 'name': 'IoT'},
        {'id': 6, 'name': 'Industrielle IT'},
    ])
    op.bulk_insert(NetworkType.__table__, [
        {'name': 'Client'},
        {'name': 'Serveur'},
        {'name': 'Invité'},
    ])
    op.bulk_insert(ScanCategory.__table__, [
        {'id': 1, 'name': 'Aucune restriction sur les scan'},
        {'id': 2, 'name': 'Scanne uniquement pendant les heures creuses ou le week-end'},
        {'id': 3, 'name': 'Scanne uniquement lorsque CyberHack est prêt et que l\'administration réseau est présente'},
    ])


def downgrade():
    """Downgrade to migration."""
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="Cbox"')
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="DNS-Server"')
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="Gateway"')
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="Firewall"')
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="IoT"')
    op.execute(f'DELETE FROM "{SystemType.__table__}" WHERE name="Industrielle IT"')
    op.execute(f'DELETE FROM "{NetworkType.__table}" WHERE name="Client"')
    op.execute(f'DELETE FROM "{NetworkType.__table}" WHERE name="Serveur"')
    op.execute(f'DELETE FROM "{NetworkType.__table}" WHERE name="Invité"')

    op.execute(f'DELETE FROM "{ScanCategory.__table}" WHERE id="1"')
    op.execute(f'DELETE FROM "{ScanCategory.__table}" WHERE id="2"')
    op.execute(f'DELETE FROM "{ScanCategory.__table}" WHERE id="3"')
