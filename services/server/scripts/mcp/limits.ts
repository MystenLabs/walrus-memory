// Match the relayer's MCP body cap. Bound collection validation separately:
// a small JSON body can contain enough elements to exhaust the shared sidecar.
export const MCP_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024;
export const MCP_MAX_TOOL_INPUT_ELEMENTS = 10_000;
