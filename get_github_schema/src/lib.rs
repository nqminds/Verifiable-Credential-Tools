use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use std::env;
use std::error::Error;

pub async fn get_schema(url: &str) -> Result<Value, Box<dyn Error>> {
    
    // Retrieve GitHub token from environment variable
    let token = env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN environment variable not set");

    // Set up HTTP client with headers
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("token {}", token))?);
    headers.insert(USER_AGENT, HeaderValue::from_static("rust-client"));

    // Send the request to the GitHub API to get the file metadata
    let response = client.get(url).headers(headers).send().await?;

    // Check if the request was successful
    if response.status().is_success() {
        // Parse the JSON response to extract the download_url
        let json_response: Value = response.json().await?;
        let download_url = json_response["download_url"]
            .as_str()
            .expect("Expected download_url to be a string");

        // Fetch the raw content from the download_url
        let raw_content_response = client.get(download_url).send().await?;
        let content = raw_content_response.text().await?;

        // Parse the YAML content to JSON and return it
        let json_value: Value = serde_yaml::from_str(&content)?;
        Ok(json_value)
    } else {
        Err(format!("Failed to fetch file metadata: {}", response.status()).into())
    }
}
