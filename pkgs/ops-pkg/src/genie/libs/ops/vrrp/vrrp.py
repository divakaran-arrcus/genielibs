# Genie
from genie.ops.base import Base


class Vrrp(Base):

    exclude = ['advertisement-sent', 'advertisement-received',
               'advertisement-dropped', 'current-priority']
