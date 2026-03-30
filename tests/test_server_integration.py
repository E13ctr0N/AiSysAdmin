import asyncio


def test_server_imports():
    """Verify server module loads without errors."""
    from agensysadmin.server import mcp
    assert mcp is not None


def test_all_tools_registered():
    """Verify all expected tools are registered on the MCP server."""
    from agensysadmin.server import mcp

    expected = {
        "list_servers",
        "system_info",
        "disk_usage",
        "check_services",
        "check_ports",
        "process_list",
        "execute_command",
        "install_package",
        "manage_service",
        "edit_config",
        "docker_ps",
        "docker_logs",
        "docker_compose",
        "docker_images",
        "check_updates",
        "firewall_status",
        "security_audit",
    }

    # Try _tool_manager._tools first (dict keyed by tool name)
    if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
        tool_names = set(mcp._tool_manager._tools.keys())
    # Fall back to _tools directly on the mcp object
    elif hasattr(mcp, "_tools"):
        raw = mcp._tools
        tool_names = set(raw.keys()) if isinstance(raw, dict) else {t.name for t in raw}
    # Fall back to async list_tools()
    else:
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}

    assert expected.issubset(tool_names), f"Missing tools: {expected - tool_names}"
