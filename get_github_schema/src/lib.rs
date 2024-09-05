use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use std::env;
use std::error::Error;

// Fetches and parses the schema from the given GitHub URL
pub fn get_schema(url: &str) -> Result<Value, Box<dyn Error>> {
    // Retrieve GitHub token from environment variable, return an error if not found
    let token =
        env::var("GITHUB_TOKEN").map_err(|_| "GITHUB_TOKEN environment variable not set")?;

    // Set up HTTP client with necessary headers (Authorization and User-Agent)
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token))?,
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("rust-client"));

    // Send request to get metadata of the file (JSON format expected)
    let response = client.get(url).headers(headers).send()?;
    if !response.status().is_success() {
        // Return an error if the request was not successful
        return Err(format!("Failed to fetch file metadata: {}", response.status()).into());
    }

    // Parse the JSON response to get the download_url field
    let json_response: Value = response.json()?;
    let download_url = json_response["download_url"]
        .as_str()
        .ok_or("download_url field missing or not a string")?;

    // Fetch the raw content from the download URL
    let raw_content = fetch_raw_content(&client, download_url)?;

    // Parse the fetched YAML content into a JSON Value and return it
    serde_yaml::from_str(&raw_content).map_err(|e| e.into())
}

// Helper function to fetch raw content from a given URL
fn fetch_raw_content(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<String, Box<dyn Error>> {
    // Send request to the download URL
    let response = client.get(url).send()?;
    if response.status().is_success() {
        // Return the raw text content if successful
        Ok(response.text()?)
    } else {
        // Return an error if the request failed
        Err(format!("Failed to fetch raw content: {}", response.status()).into())
    }
}
