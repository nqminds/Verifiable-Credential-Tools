use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde_json::Value;
use std::env;
use std::error::Error;

/// Fetches and parses the schema from the given GitHub URL
pub async fn get_schema(schema_url: &str) -> Result<Value, Box<dyn Error>> {
    let api_url = construct_github_api_url(schema_url)?;

    // Retrieve GitHub token from environment variable
    let token =
        env::var("GITHUB_TOKEN").map_err(|_| "GITHUB_TOKEN environment variable not set")?;

    // Set up HTTP client with necessary headers
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("token {}", token))?,
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("rust-client"));

    // Fetch file metadata using the GitHub API
    let response = client.get(api_url).headers(headers).send().await?;
    if !response.status().is_success() {
        return Err(format!("Failed to fetch file metadata: {}", response.status()).into());
    }

    let json_response: Value = response.json().await?;
    let download_url = json_response["download_url"]
        .as_str()
        .ok_or("download_url field missing or not a string")?;

    // Fetch the raw content from the download URL
    let raw_content = fetch_raw_content(&client, download_url).await?;

    // Parse YAML content into a JSON Value
    serde_yaml::from_str(&raw_content).map_err(Into::into)
}

/// Fetch raw content from a given URL
async fn fetch_raw_content(
    client: &reqwest::Client,
    url: &str,
) -> Result<String, Box<dyn Error>> {
    let response = client.get(url).send().await?;
    if response.status().is_success() {
        Ok(response.text().await?)
    } else {
        Err(format!("Failed to fetch raw content: {}", response.status()).into())
    }
}
/// Extract repository parts, branch, and file path from the GitHub URL and construct the API URL
fn construct_github_api_url(schema_url: &str) -> Result<String, Box<dyn Error>> {
    fn extract_repo_and_branch<'a>(schema_url: &'a str, start: &'a str) -> Result<(&'a str, &'a str), Box<dyn Error>> {
        let repo_start = schema_url.find("github.com/").ok_or("Invalid GitHub URL")? + "github.com/".len();
        let repo_end = schema_url.find(start).ok_or("Invalid GitHub URL: missing '/blob/' or '/tree/'")?;
        let repo = &schema_url[repo_start..repo_end];
        let branch_and_path = &schema_url[repo_end + start.len()..];
        Ok((repo, branch_and_path))
    }

    let (repo, branch_and_path) = if schema_url.find("/blob/").is_some() {
        extract_repo_and_branch(schema_url, "/blob/")?
    } else if schema_url.find("/tree/").is_some() {
        extract_repo_and_branch(schema_url, "/tree/")?
    } else {
        return Err("Invalid GitHub URL: missing '/blob/' or '/tree/'".into());
    };

    let path_start = branch_and_path.find('/').ok_or("Invalid GitHub URL: missing file path")?;
    let branch = &branch_and_path[..path_start];
    let file_path = &branch_and_path[path_start + 1..];

    Ok(format!(
        "https://api.github.com/repos/{}/contents/{}?ref={}",
        repo, file_path, branch
    ))
}
