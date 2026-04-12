"""CLI entrypoint for the harness: `python -m harness`."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys


def main():
    p = argparse.ArgumentParser(
        description="Vibe RE multi-model harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", help="Available commands")

    # serve — start MCP server
    serve_p = sub.add_parser("serve", help="Start the MCP server")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--config", type=str, default=None)

    # index — build RAG index
    index_p = sub.add_parser("index", help="Build the RAG index")
    index_p.add_argument("--config", type=str, default=None)

    # status — show harness status
    sub.add_parser("status", help="Show harness status")

    # run — execute a goal
    run_p = sub.add_parser("run", help="Run an analysis goal")
    run_p.add_argument("goal", help="Natural language analysis goal")
    run_p.add_argument("--project", type=str, default=None)
    run_p.add_argument("--config", type=str, default=None)

    # setup — check/install dependencies
    sub.add_parser("setup", help="Check and install dependencies")

    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.command == "serve":
        _cmd_serve(args)
    elif args.command == "index":
        asyncio.run(_cmd_index(args))
    elif args.command == "status":
        asyncio.run(_cmd_status())
    elif args.command == "run":
        asyncio.run(_cmd_run(args))
    elif args.command == "setup":
        _cmd_setup()
    else:
        p.print_help()


def _cmd_serve(args):
    """Start the MCP server."""
    from harness.config import load_config
    from harness.mcp_server import create_app

    config = load_config(args.config)
    app = create_app(config)
    if app is None:
        print("Error: fastapi not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)

    import uvicorn
    print(f"Starting MCP server on port {args.port}...")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


async def _cmd_index(args):
    """Build the RAG index."""
    from harness.config import load_config
    from harness.rag.indexer import RAGIndexer

    config = load_config(args.config)
    indexer = RAGIndexer(config.rag.persist_dir, config.rag.embedding_model)
    total = indexer.index_defaults(config.repo_root_path)
    print(f"Indexed {total} chunks into {config.rag.persist_dir}")
    print(f"Total documents in index: {indexer.count}")


async def _cmd_status():
    """Show harness status."""
    from harness.config import load_config
    from harness.gateway import check_ollama
    from harness.state.project import ProjectManager

    config = load_config()
    print(f"Orchestrator: {config.orchestrator_model_string()}")
    print(f"Worker: {config.worker_model_string()}")
    print(f"Repo root: {config.repo_root_path}")

    ollama_ok = await check_ollama(config)
    print(f"Ollama: {'OK' if ollama_ok else 'UNREACHABLE'}")

    mgr = ProjectManager(config.repo_root_path)
    projects = mgr.list_projects()
    print(f"Projects: {projects or 'none'}")


async def _cmd_run(args):
    """Execute an analysis goal."""
    from harness.config import load_config
    from harness.mcp_server import handle_re_analyze

    config = load_config(args.config)

    # Initialize harness
    from harness.mcp_server import _init_harness
    _init_harness(config)

    result = await handle_re_analyze(args.goal, args.project)
    print("\n=== Analysis Result ===")
    print(f"Goal: {result['goal']}")
    print(f"\nSteps ({len(result['steps'])}):")
    for i, step in enumerate(result["steps"], 1):
        status = "OK" if step["success"] else "FAIL"
        print(f"  {i}. [{status}] {step['tool']}")
        if step["output_preview"]:
            # Indent output preview
            for line in step["output_preview"].split("\n")[:5]:
                print(f"     {line}")
        if step["error"]:
            print(f"     ERROR: {step['error']}")


def _cmd_setup():
    """Check dependencies."""
    print("Checking harness dependencies...\n")

    deps = {
        "pydantic": "pydantic",
        "pydantic_ai": "pydantic-ai",
        "yaml": "pyyaml",
        "chromadb": "chromadb",
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "litellm": "litellm",
    }

    missing = []
    for module, package in deps.items():
        try:
            __import__(module)
            print(f"  OK  {package}")
        except ImportError:
            print(f"  MISSING  {package}")
            missing.append(package)

    # Check repo tools
    print("\nChecking repo tools...")
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "verify_install.py"],
            capture_output=True, text=True, timeout=30,
        )
        print(r.stdout)
    except Exception as e:
        print(f"  Could not run verify_install.py: {e}")

    if missing:
        print(f"\nInstall missing packages: pip install {' '.join(missing)}")
    else:
        print("\nAll harness dependencies OK.")


if __name__ == "__main__":
    main()
