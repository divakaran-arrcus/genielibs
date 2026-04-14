# Genie
from genie.ops.base import Base


class Bfd(Base):

    exclude = ['transmitted-packets', 'received-packets', 'session-up-time']
