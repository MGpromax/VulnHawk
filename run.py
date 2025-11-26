#!/usr/bin/env python3
"""
VulnHawk - Web Application Vulnerability Scanner

Main entry point for the application.
"""

import os
import sys
import click
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@click.group()
@click.version_option(version='1.0.0', prog_name='VulnHawk')
def cli():
    """VulnHawk - Advanced Web Application Vulnerability Scanner"""
    pass


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def web(host, port, debug):
    """Start the web interface."""
    from app import create_app, socketio

    config = 'development' if debug else 'production'
    app = create_app(config)

    click.echo(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗    ║
    ║   ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗   ║
    ║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║   ║
    ║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║   ║
    ║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║   ║
    ║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ║
    ║                                                           ║
    ║   Web Application Vulnerability Scanner v1.0.0            ║
    ║   Created by Manoj Gowda                                  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝

    Starting web server at http://{host}:{port}
    Press Ctrl+C to stop
    """)

    socketio.run(app, host=host, port=port, debug=debug)


@cli.command()
@click.argument('url')
@click.option('--modules', '-m', multiple=True, help='Scan modules to use')
@click.option('--depth', default=5, help='Maximum crawl depth')
@click.option('--pages', default=100, help='Maximum pages to crawl')
@click.option('--output', '-o', help='Output file for report')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'pdf']), default='json', help='Report format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(url, modules, depth, pages, output, format, verbose):
    """Run a vulnerability scan against a target URL."""
    import asyncio
    import json
    from datetime import datetime

    click.echo(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║   VulnHawk CLI Scanner                                    ║
    ╚═══════════════════════════════════════════════════════════╝

    Target: {url}
    Modules: {', '.join(modules) if modules else 'All'}
    Max Depth: {depth}
    Max Pages: {pages}
    """)

    async def run_scan():
        from app.scanner.core.engine import ScannerEngine, ScanConfig

        # Configure scan
        config = ScanConfig(
            max_depth=depth,
            max_pages=pages,
            scan_modules=list(modules) if modules else [
                'xss', 'sqli', 'csrf', 'headers', 'info_disclosure', 'lfi', 'open_redirect', 'ssl'
            ]
        )

        vulnerabilities = []

        def on_progress(data):
            if verbose:
                click.echo(f"  [{data['progress']}%] {data.get('message', '')}")

        def on_vulnerability(vuln):
            vulnerabilities.append(vuln)
            severity = vuln.get('severity', 'unknown').upper()
            name = vuln.get('name', 'Unknown')
            click.secho(f"  [!] Found: {severity} - {name}", fg='red' if severity in ['CRITICAL', 'HIGH'] else 'yellow')

        scanner = ScannerEngine(
            config=config,
            progress_callback=on_progress,
            vulnerability_callback=on_vulnerability
        )

        click.echo("Starting scan...")
        click.echo("-" * 50)

        results = await scanner.scan(url)

        click.echo("-" * 50)
        click.echo(f"\nScan completed!")
        click.echo(f"Status: {results['status']}")
        click.echo(f"Vulnerabilities found: {len(vulnerabilities)}")

        # Generate report
        if output:
            report_data = {
                'target': url,
                'scan_date': datetime.utcnow().isoformat(),
                'status': results['status'],
                'vulnerabilities': vulnerabilities,
                'summary': {
                    'total': len(vulnerabilities),
                    'critical': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
                    'high': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                    'medium': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                    'low': len([v for v in vulnerabilities if v.get('severity') == 'low']),
                    'info': len([v for v in vulnerabilities if v.get('severity') == 'info']),
                }
            }

            if format == 'json':
                with open(output, 'w') as f:
                    json.dump(report_data, f, indent=2)
            elif format == 'html':
                # Generate HTML report
                from app.reports.html_report import generate_html_report
                # Note: This would need a mock scan object for CLI
                click.echo("HTML report generation requires database. Use web interface.")
            elif format == 'pdf':
                click.echo("PDF report generation requires database. Use web interface.")

            click.echo(f"Report saved to: {output}")

        return vulnerabilities

    vulnerabilities = asyncio.run(run_scan())

    # Print summary
    click.echo("\n" + "=" * 50)
    click.echo("VULNERABILITY SUMMARY")
    click.echo("=" * 50)

    severity_counts = {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
    }
    for v in vulnerabilities:
        sev = v.get('severity', 'info').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    click.secho(f"  Critical: {severity_counts['critical']}", fg='red')
    click.secho(f"  High:     {severity_counts['high']}", fg='red')
    click.secho(f"  Medium:   {severity_counts['medium']}", fg='yellow')
    click.secho(f"  Low:      {severity_counts['low']}", fg='green')
    click.secho(f"  Info:     {severity_counts['info']}", fg='blue')
    click.echo("-" * 50)
    click.echo(f"  Total:    {len(vulnerabilities)}")


@cli.command()
def initdb():
    """Initialize the database."""
    from app import create_app, db

    app = create_app('development')

    with app.app_context():
        db.create_all()
        click.echo("Database initialized successfully!")


@cli.command()
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Admin password')
def createadmin(username, email, password):
    """Create an admin user."""
    from app import create_app, db
    from app.models import User

    app = create_app('development')

    with app.app_context():
        try:
            user = User(
                username=username,
                email=email,
                password=password,
                is_admin=True
            )
            db.session.add(user)
            db.session.commit()
            click.echo(f"Admin user '{username}' created successfully!")
        except ValueError as e:
            click.echo(f"Error: {e}", err=True)
        except Exception as e:
            db.session.rollback()
            click.echo(f"Error creating user: {e}", err=True)


@cli.command()
def demo():
    """Start the vulnerable demo application for testing."""
    click.echo("Starting vulnerable demo application...")
    click.echo("Demo app available at: http://localhost:5001")

    from tests.vulnerable_app import create_vulnerable_app
    app = create_vulnerable_app()
    app.run(host='127.0.0.1', port=5001, debug=True)


if __name__ == '__main__':
    cli()
