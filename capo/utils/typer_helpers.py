"""Shared Typer utilities."""

from collections.abc import Callable

import click
import typer


def fallback_group(callback: Callable[[list[str]], None]) -> type[typer.core.TyperGroup]:
    """Create a TyperGroup subclass that routes unknown subcommands to *callback*.

    Usage:
        def _my_fallback(args: list[str]):
            ...

        app = typer.Typer(cls=fallback_group(_my_fallback))
    """

    class _FallbackGroup(typer.core.TyperGroup):
        def resolve_command(self, ctx, args):
            try:
                return super().resolve_command(ctx, args)
            except click.UsageError:
                callback(list(args))
                raise typer.Exit()

    return _FallbackGroup
