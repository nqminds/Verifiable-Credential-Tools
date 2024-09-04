use get_github_schema::get_schema;
use tokio;

#[tokio::test]
async fn test_get_schema() {
    let url = "https://api.github.com/repos/nqminds/ClaimCascade/contents/packages/schemas/src/fact.yaml?ref=event_store_rework";
    let schema = get_schema(url).await.expect("Failed to fetch schema");
    assert!(schema.is_object());
}

#[tokio::test]
async fn test_get_schema_fail() {
    // Intentionally incorrect URL (nonexistent file path)
    let url = "https://api.github.com/repos/nqminds/ClaimCascade/contents/packages/schemas/src/invalid_file.yaml?ref=event_store_rework";
    
    // This should fail because the file doesn't exist or the URL is incorrect
    let result = get_schema(url).await;

    // Since we expect this to fail, we assert that the result is an error
    assert!(result.is_err(), "Expected the request to fail, but it succeeded.");
}
