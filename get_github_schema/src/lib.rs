use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use std::env;
use std::error::Error;

/// Fetches and parses the schema from the given GitHub URL
pub fn get_schema(schema_url: &str) -> Result<Value, Box<dyn Error>> {
    let api_url = construct_github_api_url(schema_url)?;

    // Retrieve GitHub token from environment variable
    let token =
        env::var("GITHUB_TOKEN").map_err(|_| "GITHUB_TOKEN environment variable not set")?;

    // Set up HTTP client with necessary headers
    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token))?,
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("rust-client"));

    // Fetch file metadata using the GitHub API
    let response = client.get(&api_url).headers(headers).send()?;
    if !response.status().is_success() {
        return Err(format!("Failed to fetch file metadata: {}", response.status()).into());
    }

    let json_response: Value = response.json()?;
    let download_url = json_response["download_url"]
        .as_str()
        .ok_or("download_url field missing or not a string")?;

    // Fetch the raw content from the download URL
    let raw_content = fetch_raw_content(&client, download_url)?;

    // Parse YAML content into a JSON Value
    serde_yaml::from_str(&raw_content).map_err(Into::into)
}

/// Fetch raw content from a given URL
fn fetch_raw_content(client: &Client, url: &str) -> Result<String, Box<dyn Error>> {
    let response = client.get(url).send()?;
    if response.status().is_success() {
        Ok(response.text()?)
    } else {
        Err(format!("Failed to fetch raw content: {}", response.status()).into())
    }
}

/// Extract repository parts, branch, and file path from the GitHub URL and construct the API URL
fn construct_github_api_url(schema_url: &str) -> Result<String, Box<dyn Error>> {
    let repo_start =
        schema_url.find("github.com/").ok_or("Invalid GitHub URL")? + "github.com/".len();

    let (repo, branch_and_path) = if let Some(blob_start) = schema_url.find("/blob/") {
        let repo_end = blob_start;
        let repo = &schema_url[repo_start..repo_end];

        let blob_start = blob_start + "/blob/".len();
        let branch_and_path = &schema_url[blob_start..];
        (repo, branch_and_path)
    } else if let Some(tree_start) = schema_url.find("/tree/") {
        let repo_end = tree_start;
        let repo = &schema_url[repo_start..repo_end];

        let tree_start = tree_start + "/tree/".len();
        let branch_and_path = &schema_url[tree_start..];
        (repo, branch_and_path)
    } else {
        return Err("Invalid GitHub URL: missing '/blob/' or '/tree/'".into());
    };

    let path_start = branch_and_path
        .find('/')
        .ok_or("Invalid GitHub URL: missing file path")?;
    let branch = &branch_and_path[..path_start];
    let file_path = &branch_and_path[path_start + 1..];

    Ok(format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        repo, file_path, branch
    ))
}
