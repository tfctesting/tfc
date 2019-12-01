import typing

from typing import Iterable, Iterator, List, Optional

from src.common.db_contacts import Contact
from src.common.statics     import WIN_TYPE_CONTACT

if typing.TYPE_CHECKING:
    from src.common.db_groups import Group


class MockWindow(Iterable[Contact]):
    """\
    Mock window simplifies queueing of message assembly packets for
    automatically generated group management and key delivery messages.
    """

    def __init__(self, uid: bytes, contacts: List['Contact']) -> None:
        """Create a new MockWindow object."""
        self.window_contacts = contacts
        self.type            = WIN_TYPE_CONTACT
        self.group           = None  # type: Optional[Group]
        self.name            = None  # type: Optional[str]
        self.uid             = uid
        self.log_messages    = self.window_contacts[0].log_messages

    def __iter__(self) -> Iterator[Contact]:
        """Iterate over contact objects in the window."""
        yield from self.window_contacts
