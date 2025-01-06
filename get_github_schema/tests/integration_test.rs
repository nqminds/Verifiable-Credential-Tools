use get_github_schema::get_schema;

#[test]
fn test_get_schema() {
    let url = "https://github.com/nqminds/claim-cascade-schemas/blob/master/src/schema.json";
    let schema = get_schema(url).expect("Failed to fetch schema");

    // Assert that the schema is a JSON object
    assert!(schema.is_object(), "Expected schema to be a JSON object");
}

#[test]
fn test_get_schema_fail() {
    // Intentionally incorrect URL (nonexistent file path)
    let url = "https://github.com/nqminds/ClaimCascade/tree/event_store_rework/packages/schemas/src/INVALID_FILE.yaml";

    // This should fail because the file doesn't exist or the URL is incorrect
    let result = get_schema(url);

    // Since we expect this to fail, we assert that the result is an error
    assert!(
        result.is_err(),
        "Expected the request to fail, but it succeeded."
    );
}
