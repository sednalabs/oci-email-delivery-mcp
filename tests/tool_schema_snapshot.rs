use mcp_toolkit_testing::assert_tool_schema_snapshot;
use oci_email_delivery_mcp::{tests_support::FixtureBackend, OciEmailMcpServer};
use std::{path::PathBuf, sync::Arc};

#[test]
fn tool_schema_snapshot_contract_is_stable() {
    let server = OciEmailMcpServer::with_backend(Arc::new(FixtureBackend))
        .unwrap_or_else(|err| panic!("server inventory: {err}"));
    let snapshot_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/tool_schema_snapshot.v1.json");
    assert_tool_schema_snapshot(snapshot_path, &server.tool_schema_snapshot());
}
