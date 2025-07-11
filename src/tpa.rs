use anyhow::{Result, anyhow};
use log::{error, info};
use reqwest::{Response, StatusCode, blocking::Client};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Labels {
    pub source: Option<String>,
    pub file: Option<String>,
    #[serde(rename = "type")]
    pub adv_type: String,
    pub importer: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Advisories {
    pub identifier: String,
    pub score: Option<f32>,
    pub severity: Option<String>,
    pub labels: Labels,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vulnerability {
    pub identifier: String,
    pub title: Option<String>,
    pub average_severity: Option<String>,
    pub average_score: Option<f32>,
    pub advisories: Vec<Advisories>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TPAVulns {
    pub items: Vec<Vulnerability>,
}

pub async fn fetch_tpa_data(
    tpa_baseUrl: &str,
    severity: &str,
    limitter: &str,
    tpa_access_token: &str,
) -> Result<TPAVulns> {
    let tpa_api_vuln_endpoint = format!(
        "{}/api/v2/vulnerability?limit={}&offset=0&q=base_severity%3D{}&",
        tpa_baseUrl,limitter, severity,
    );
    info!("Retrieving TPA details for {} Severity", severity);
    let response = reqwest::Client::new()
        .get(tpa_api_vuln_endpoint)
        .header("Authorization", format!("Bearer {}", tpa_access_token))
        .send()
        .await
        .expect("Error while sending request");
    println!("{:#?}", response.status());
    if response.status() == StatusCode::OK {
        let text_res = response
            .text()
            .await
            .expect("Error while converting to text");
        let tpa_response: TPAVulns = serde_json::from_str(&text_res).expect("Error while parsing");
        Ok(tpa_response)
    } else {
        Err(anyhow!(
            "Error retriving TPA response from Endpoint. Response code {}",
            response.status()
        ))
    }
}
