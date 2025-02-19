use get_github_schema::get_schema;

#[tokio::test]
async fn test_get_schema() {
    let url = "https://github.com/nqminds/claim-cascade-schemas/blob/master/src/schema.json";
    let schema = get_schema(url).await.expect("Failed to fetch schema");

    // Assert that the schema is a JSON object
    assert!(schema.is_object(), "Expected schema to be a JSON object");
}

#[tokio::test]
async fn test_get_schema_fail() {
    // Intentionally incorrect URL (nonexistent file path)
    let url = "https://github.com/nqminds/ClaimCascade/tree/event_store_rework/packages/schemas/src/INVALID_FILE.yaml";

    // This should fail because the file doesn't exist or the URL is incorrect
    let result = get_schema(url).await;

    // Since we expect this to fail, we assert that the result is an error
    assert!(
        result.is_err(),
        "Expected the request to fail, but it succeeded."
    );
}

#[tokio::test]
async fn test_get_identity_schema() {
    let url = "https://github.com/nqminds/ClaimCascade/tree/main/packages/schemas/src/identity.json";
    let schema = get_schema(url).await.expect("Failed to fetch schema");

    // Assert that the schema is a JSON object
    assert!(schema.is_object(), "Expected schema to be a JSON object");
}
#[tokio::test]
async fn test_get_schema_schema() {
    let url = "https://github.com/nqminds/ClaimCascade/blob/main/packages/schemas/src/schema.json";
    let schema = get_schema(url).await.expect("Failed to fetch schema");

    // Assert that the schema is a JSON object
    assert!(schema.is_object(), "Expected schema to be a JSON object");
}


#[tokio::test]
async fn test_get_schema_schema_again() {
    let url = "https://github.com/nqminds/ClaimCascade/blob/main/packages/schemas/src/schema.json";
    let schema = get_schema(url).await.expect("Failed to fetch schema");

    // Assert that the schema is a JSON object
    assert!(schema.is_object(), "Expected schema to be a JSON object");
}