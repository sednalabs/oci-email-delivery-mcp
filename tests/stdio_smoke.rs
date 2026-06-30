use mcp_toolkit_testing::stdio_contract::{assert_stdio_tools_list, StdioMcpProcess};
use serde_json::json;

#[test]
fn stdio_initializes_and_lists_tools() {
    assert_stdio_tools_list(
        env!("CARGO_BIN_EXE_oci-email-delivery-mcp"),
        &[
            "oci_email_events",
            "oci_email_ledger_window",
            "oci_email_metrics",
            "oci_email_send_readiness",
            "oci_email_status",
            "oci_email_suppressions",
            "oci_email_trace_message",
            "oci_email_watch_window",
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
    assert_eq!(tools.len(), 8);

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

    let ledger = tools
        .iter()
        .find(|tool| tool["name"] == "oci_email_ledger_window")
        .expect("ledger tool");
    assert_eq!(
        ledger["inputSchema"]["required"],
        json!(["start_time", "end_time"])
    );
    assert!(ledger["inputSchema"]["properties"]
        .as_object()
        .expect("ledger properties")
        .contains_key("sender_domain"));

    let watch = tools
        .iter()
        .find(|tool| tool["name"] == "oci_email_watch_window")
        .expect("watch-window tool");
    assert_eq!(
        watch["inputSchema"]["required"],
        json!(["start_time", "end_time"])
    );
    assert!(watch["inputSchema"]["properties"]
        .as_object()
        .expect("watch properties")
        .contains_key("source_domain"));

    let send_readiness = tools
        .iter()
        .find(|tool| tool["name"] == "oci_email_send_readiness")
        .expect("send-readiness tool");
    assert_eq!(
        send_readiness["inputSchema"]["required"],
        json!([
            "start_time",
            "end_time",
            "campaign_id",
            "batch_id",
            "expected_ledger_rows"
        ])
    );
    let send_readiness_properties = send_readiness["inputSchema"]["properties"]
        .as_object()
        .expect("send-readiness properties");
    assert!(send_readiness_properties.contains_key("expected_ledger_rows"));
    assert!(send_readiness_properties.contains_key("campaign_id"));
    assert!(send_readiness_properties.contains_key("batch_id"));
}
