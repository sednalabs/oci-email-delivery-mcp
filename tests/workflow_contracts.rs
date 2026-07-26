const CODE_COVERAGE_WORKFLOW: &str = include_str!("../.github/workflows/code-coverage.yml");

#[test]
fn cobertura_generation_and_artifact_remain_the_required_gate() {
    let (required_job, _) = CODE_COVERAGE_WORKFLOW
        .split_once("  code-quality-upload:")
        .expect("workflow must keep the optional upload in a separate job");

    let generate_index = required_job
        .find("      - name: Generate coverage")
        .expect("required job must generate coverage");
    let artifact_index = required_job
        .find("      - name: Upload Cobertura report")
        .expect("required job must retain the generated report");

    assert!(generate_index < artifact_index);
    assert!(required_job.contains("name: Rust Cobertura coverage"));
    assert!(required_job.contains(
        "cargo llvm-cov --all-targets --all-features \\\n            --cobertura --output-path coverage/oci-email-delivery-mcp.xml"
    ));
    assert!(required_job
        .contains("uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"));
    assert!(required_job.contains("if-no-files-found: error"));
    assert!(!required_job.contains("continue-on-error"));
    assert!(!required_job.contains("code-quality: write"));
}

#[test]
fn external_code_quality_reporting_is_capability_and_same_repository_gated() {
    let (_, optional_job) = CODE_COVERAGE_WORKFLOW
        .split_once("  code-quality-upload:")
        .expect("workflow must define the optional upload job");

    assert!(optional_job.contains("vars.CODE_QUALITY_UPLOAD_ENABLED == 'true'"));
    assert!(optional_job.contains("github.event_name != 'pull_request'"));
    assert!(optional_job
        .contains("github.event.pull_request.head.repo.full_name == github.repository"));
    assert!(optional_job.contains("name: GitHub Code Quality upload"));
    assert!(optional_job.contains("needs: rust-coverage"));
    assert!(optional_job.contains("code-quality: write"));
    assert!(optional_job
        .contains("uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"));
    assert!(optional_job
        .contains("uses: actions/upload-code-coverage@abb5995db9e0199b0e2bb9dbd136fce4cb1ec4d3"));
    assert!(!optional_job.contains("continue-on-error"));
}
