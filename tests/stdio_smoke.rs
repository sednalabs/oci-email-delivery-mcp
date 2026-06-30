use mcp_toolkit_testing::stdio_contract::{assert_stdio_tools_list, StdioMcpProcess};
use serde_json::json;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_oci-email-delivery-mcp"),
        &[
            "oci_email_events",
            "oci_email_metrics",
            "oci_email_status",
            "oci_email_suppressions",
            "oci_email_trace_message",
        ],
    );
}

#[test]
fn stdio_tools_list_includes_input_schemas() {
    let mut process = StdioMcpProcess::start(env!("CARGO_BIN_EXE_oci-email-delivery-mcp"));
    process.send(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    let response = process.response(2);
    let tools = response["result"]["tools"]
        .as_array()
        .expect("tools/list array");
    assert_eq!(tools.len(), 5);

    for tool in tools {
        let name = tool["name"].as_str().expect("tool name");
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["type"], "object",
            "{name} served inputSchema must be an object"
        );
    }

    let metrics = tools
        .iter()
        .find(|tool| tool["name"] == "oci_email_metrics")
        .expect("metrics tool");
    assert_eq!(
        metrics["inputSchema"]["required"],
        json!(["start_time", "end_time"])
    );
    assert!(metrics["inputSchema"]["properties"]
        .as_object()
        .expect("metrics properties")
        .contains_key("resource_domain"));
}
