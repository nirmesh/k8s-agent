from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from backend.mcp.server import MCPHandler

router = APIRouter(tags=["mcp"])

_handler: MCPHandler | None = None


def _get_handler() -> MCPHandler:
    global _handler
    if _handler is None:
        _handler = MCPHandler()
    return _handler


@router.post("/mcp")
async def mcp_endpoint(request: Request):
    """MCP JSON-RPC endpoint. Exposes all registered providers as MCP tools."""
    body = await request.json()
    response = _get_handler().handle(body)
    status_code = 200 if "error" not in response else 400
    return JSONResponse(content=response, status_code=status_code)
