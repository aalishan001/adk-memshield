"""Exception types raised by adk-memshield."""

from __future__ import annotations


class MemShieldError(Exception):
    """Base class for adk-memshield errors."""


class MemShieldConfigurationError(MemShieldError):
    """The database connection or table cannot enforce Row-Level Security.

    Raised before any memory is read or written when the connecting role is a superuser
    or has BYPASSRLS, when the table does not have forced row-level security, or when the
    expected policies are missing. memshield fails closed rather than run unprotected.
    """


class MemShieldIdentityError(MemShieldError, PermissionError):
    """The caller's identity could not be verified.

    Raised when an identity verifier is configured and no token is bound, the token is
    invalid, expired or issued for another audience, or the token's user does not match
    the user the framework asked for. Messages never contain the token itself.
    """
