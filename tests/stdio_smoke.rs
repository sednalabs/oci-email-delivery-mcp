use mcp_toolkit_testing::stdio_contract::assert_stdio_tools_list;

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
