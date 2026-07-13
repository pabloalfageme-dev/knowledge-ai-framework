"""Bootstrap CLI: initializes the first organization and admin user."""
import asyncio
import sys

import typer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.auth.service import AlreadyInitializedError, create_first_org_and_admin
from src.core.config import settings

app = typer.Typer(add_completion=False)


async def _run_setup(org_name: str, admin_email: str, admin_password: str) -> None:
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with session_factory() as session:
            async with session.begin():
                org_id, user_id = await create_first_org_and_admin(
                    session, org_name, admin_email, admin_password
                )
        typer.echo("Setup complete!")
        typer.echo(f"  Organization ID : {org_id}")
        typer.echo(f"  Admin user ID   : {user_id}")
    finally:
        await engine.dispose()


@app.command()
def setup(
    org_name: str = typer.Option(..., "--org-name", help="Name of the first organization"),
    admin_email: str = typer.Option(..., "--admin-email", help="Admin user email address"),
    admin_password: str = typer.Option(
        ..., "--admin-password", help="Admin user password", hide_input=True
    ),
) -> None:
    """Bootstrap the system: create the first organization and admin user."""
    try:
        asyncio.run(_run_setup(org_name, admin_email, admin_password))
    except AlreadyInitializedError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()