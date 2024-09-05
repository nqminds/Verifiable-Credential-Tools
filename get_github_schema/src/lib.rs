use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use std::env;
use std::error::Error;

// Fetches and parses the schema from the given GitHub URL
pub fn get_schema(schema_url: &str) -> Result<Value, Box<dyn Error>> {
    let url = get_api_url(schema_url);

    // Retrieve GitHub token from environment variable; return an error if not found
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

// Extract repository parts from the URL
fn extract_repo_parts(url: &str) -> &str {
    let start = url.find("github.com/").unwrap() + "github.com/".len();
    let end = url.find("/tree/").unwrap();
    &url[start..end]
}

// Extract file path from the URL
fn extract_file_path(url: &str) -> &str {
    let start = url.find("/tree/").unwrap() + "/tree/".len();
    let file_path_start = url[start..].find('/').unwrap() + start + 1;
    &url[file_path_start..]
}

// Extract branch name from the URL
fn extract_branch(url: &str) -> &str {
    let start = url.find("/tree/").unwrap() + "/tree/".len();
    let end = url[start..].find('/').unwrap() + start;
    &url[start..end]
}

// Generate the GitHub API URL for the raw file content
fn get_api_url(schema_url: &str) -> String {
    let repo = extract_repo_parts(schema_url);
    let file_path = extract_file_path(schema_url);
    let branch = extract_branch(schema_url);

    format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        repo, file_path, branch
    )
}
