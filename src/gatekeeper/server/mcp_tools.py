"""MCP tools the agent calls. Every tool is a stub for now; GK-7 makes them real."""

from fastmcp import FastMCP

mcp = FastMCP("Gatekeeper")


#This will be implemented in GK-7
@mcp.tool
def run_command(command: str, cwd: str) -> str:
    """Run a shell command in the given working directory."""
    return "run_command is not implemented yet"


@mcp.tool
def write_file(path: str, content: str) -> str:
    """Write content to a file, replacing anything already there."""
    return "write_file is not implemented yet"


@mcp.tool
def read_file(path: str) -> str:
    """Read the contents of a file."""
    return "read_file is not implemented yet"


@mcp.tool
def fetch_url(url: str) -> str:
    """Fetch the contents of a URL."""
    return "fetch_url is not implemented yet"
