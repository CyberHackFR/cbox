"""empty message

Revision ID: 2bcd96b138e4
Revises: 045ed1db87f6
Create Date: 2020-04-22 08:22:55.727836

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from source.models import Role

# revision identifiers, used by Alembic.
revision = '2bcd96b138e4'
down_revision = '045ed1db87f6'
branch_labels = None
depends_on = None


def upgrade():
    """Upgrade to migration."""
    op.bulk_insert(Role.__table__,
                   [
                       {'id': 1, 'name': 'Super Admin', 'description': 'Super Admin'},
                       {'id': 2, 'name': 'Filtre', 'description': 'Affichage et création de filtres'},
                       {'id': 3, 'name': 'Updates', 'description': 'Afficher et démarrer les mises à jour'},
                       {'id': 4, 'name': 'User-Management', 'description': 'Modification et création d\'utilisateurs'},
                       {'id': 5, 'name': 'FAQ', 'description': 'Consulter la FAQ et utiliser le formulaire de contact CyberHack'},
                       {'id': 6, 'name': 'Dashboards-Master', 'description': 'Gestion du tableau de bord'},
                       {'id': 7, 'name': 'SIEM', 'description': 'Tableau de bord du SIEM'},
                       {'id': 8, 'name': 'Vulnérabilités', 'description': 'Tableaux de bord de vulnérabilité'},
                       {'id': 9, 'name': 'Réseau', 'description': 'Tableaux de bord du réseau'},
                   ])
    # ### end Alembic commands ###


def downgrade():
    """Downgrade to migration."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.execute('DELETE FROM "role" WHERE id<10')
    # ### end Alembic commands ###