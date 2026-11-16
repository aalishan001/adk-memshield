"""The ``pre_write`` hook: inspect each memory before it is stored.

A hook receives the verified identity and the pending memory and returns a decision:

* :class:`Allow` - store it as labelled.
* :class:`Downlabel` - store it with tighter labels (``private`` instead of
  ``tenant_shared``, a higher ``min_clearance``, or a narrower compartment set).
* :class:`Block` - do not store it.

Hooks may only tighten. A decision that would widen who can read the memory raises
:class:`ValueError` and the memory is not stored. If a hook raises, memshield treats it
as a block (fail closed). The database policies stay authoritative either way.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from .identity import MemShieldIdentity, validate_compartments

Scope = Literal["private", "tenant_shared"]


@dataclass(frozen=True)
class PendingMemory:
    """A memory about to be written, with the labels it will be stored under."""

    text: str
    author: str
    scope: Scope
    min_clearance: int
    compartments: tuple[str, ...] = field(default_factory=tuple)
    session_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Allow:
    """Store the memory as labelled."""


@dataclass(frozen=True)
class Downlabel:
    """Store the memory with tighter labels. ``None`` keeps a label unchanged."""

    scope: Scope | None = None
    min_clearance: int | None = None
    compartments: tuple[str, ...] | None = None


@dataclass(frozen=True)
class Block:
    """Do not store the memory."""

    reason: str = "blocked by pre_write hook"


Decision = Allow | Downlabel | Block
PreWriteHook = Callable[[MemShieldIdentity, PendingMemory], Decision]


def _compartments_tighter_or_equal(old: tuple[str, ...], new: tuple[str, ...]) -> bool:
    """True if readers allowed by ``new`` are a subset of readers allowed by ``old``.

    An empty set means "no compartment restriction" (widest). A non-empty set admits
    callers holding any of its compartments, so a subset is narrower.
    """
    if not new:
        return not old
    if not old:
        return True
    return set(new) <= set(old)


def apply_downlabel(pending: PendingMemory, decision: Downlabel) -> PendingMemory:
    """Return ``pending`` with ``decision`` applied, refusing anything that widens access."""
    scope = decision.scope if decision.scope is not None else pending.scope
    min_clearance = (
        decision.min_clearance if decision.min_clearance is not None else pending.min_clearance
    )
    compartments = (
        validate_compartments(decision.compartments)
        if decision.compartments is not None
        else pending.compartments
    )
    if pending.scope == "private" and scope != "private":
        raise ValueError("pre_write hook tried to widen scope from private to tenant_shared")
    if isinstance(min_clearance, bool) or not isinstance(min_clearance, int) or not 1 <= min_clearance <= 5:
        raise ValueError("pre_write hook returned an invalid min_clearance")
    if min_clearance < pending.min_clearance:
        raise ValueError("pre_write hook tried to lower min_clearance")
    # Compartments only restrict who may read tenant_shared rows; a private row is readable
    # by its owner alone whatever its compartments.
    if scope == "tenant_shared" and not _compartments_tighter_or_equal(
        pending.compartments, compartments
    ):
        raise ValueError("pre_write hook tried to widen the compartment set")
    return replace(pending, scope=scope, min_clearance=min_clearance, compartments=compartments)
