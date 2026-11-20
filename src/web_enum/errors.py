"""Exception hierarchy.

Expected, user-facing failures subclass :class:`WebEnumError` and carry an
``exit_code``; the CLI turns them into a clean message and that exit code.

:class:`ModuleError` is different: it is raised *inside* one analysis module
(fingerprint, headers, discovery, forms) or by an external tool, and never stops
the scan. The runner records it in that module's result and the rest carry on.
"""

from __future__ import annotations


class WebEnumError(Exception):
    """Base class for expected, user-facing errors."""

    exit_code: int = 1


class ConfigError(WebEnumError):
    """The YAML configuration (or a command-line option) is invalid."""

    exit_code = 2


class InvalidTargetError(WebEnumError):
    """The URL given by the user is not a valid http(s) target."""

    exit_code = 2


class ToolNotFoundError(WebEnumError):
    """An external tool was explicitly requested (e.g. backend: ffuf) but is not installed."""

    exit_code = 3


class ScopeError(WebEnumError):
    """The target is not in the authorised scope and --authorized was not given."""

    exit_code = 4


class TargetUnreachableError(WebEnumError):
    """The target did not answer at all: nothing to analyse."""

    exit_code = 5


class ModuleError(Exception):
    """One module or external tool failed; recorded in the report, the scan goes on.

    Not a WebEnumError on purpose: the runner handles it, not the CLI.
    """


class RequestFailedError(ModuleError):
    """A request could not be completed (network error, timeout, redirect loop)."""


class BudgetExhaustedError(ModuleError):
    """The per-scan request budget (limits.max_requests) is used up."""


class OutOfScopeRequestError(ModuleError):
    """Something tried to request a URL outside the target origin (refused)."""
