use oci_email_delivery_mcp::{OciEmailConfig, OciEmailMcpServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = OciEmailMcpServer::new(OciEmailConfig::from_env()?)?;
    mcp_toolkit::server::stdio::serve_stdio(server).await?;
    Ok(())
}
