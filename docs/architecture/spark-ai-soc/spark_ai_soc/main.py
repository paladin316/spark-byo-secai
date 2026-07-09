import typer
from .orchestrator import Orchestrator

app = typer.Typer(help="SPARK AI SOC Phase 0 CLI")

@app.command()
def analyze_cve(cve: str, workflow: str = "cve_to_twpp"):
    result = Orchestrator().run(workflow=workflow, input_ref=cve)
    typer.echo(result)

@app.command()
def analyze_poc(path: str, workflow: str = "poc_to_attack_paths"):
    result = Orchestrator().run(workflow=workflow, input_ref=path)
    typer.echo(result)

@app.command()
def create_hunt(intel_path: str, platform: str = "crowdstrike"):
    result = Orchestrator().run(workflow="intel_to_hunt", input_ref=intel_path, platform=platform)
    typer.echo(result)

@app.command()
def create_ads(hunt_path: str):
    result = Orchestrator().run(workflow="hunt_to_ads", input_ref=hunt_path)
    typer.echo(result)

if __name__ == "__main__":
    app()
