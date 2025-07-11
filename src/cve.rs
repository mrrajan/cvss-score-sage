use anyhow::{Result, anyhow};
use cvss::v3::Base;
use log::{error, info};
use reqwest::{Response, StatusCode};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum MetricsWrapper {
    CvssV2_0 { cvssV2_0: CVSSv2 },
    CvssV3_0 { cvssV3_0: CVSS },
    CvssV3_1 { cvssV3_1: CVSS },
    CvssV4_0 { cvssV4_0: CVSS },
    Other { other: CVSSOther },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVSSOther {
    #[serde(rename = "type")]
    pub othertype: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVSS {
    pub baseScore: f32,
    pub vectorString: String,
    pub baseSeverity: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CVSSv2 {
    #[serde(rename = "baseScore")]
    pub base_score: f32,

    #[serde(rename = "vectorString")]
    pub vector_string: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Serialize, Debug, Deserialize)]
pub struct CNAcontent {
    pub descriptions: Vec<Description>,
    pub metrics: Option<Vec<Option<MetricsWrapper>>>,
}
#[derive(Serialize, Debug, Deserialize)]
pub struct ADPcontent {
    pub title: Option<String>,
    pub metrics: Option<Vec<Option<MetricsWrapper>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVEContainers {
    pub cna: CNAcontent,
    pub adp: Option<Vec<ADPcontent>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CVEListV5 {
    pub containers: CVEContainers,
}

pub async fn fetch_cvev5_data(cve_id: &str) -> Result<CVEListV5> {
    let cve_tokens: Vec<_> = cve_id.split("-").collect();
    if cve_tokens.len() != 3 {
        return Err(anyhow!("Invalid CVE ID format: {}", cve_id));
    }
    let dir = cve_tokens[2];
    let max_len = dir.len().min(4);
    for i in 1..max_len {
        let cve_dir = dir[..i].to_string() + "xxx";
        let git_cve_url = format!(
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/{}/{}/{}.json",
            cve_tokens[1], cve_dir, cve_id
        );
        let response = reqwest::Client::new()
            .get(git_cve_url)
            .header("Accept", "application/json")
            .send()
            .await
            .expect("Error from Response");
        if (response.status() == StatusCode::OK) {
            let response_text = response
                .text()
                .await
                .expect("Error while parsing the response");
            let cve_json: CVEListV5 =
                serde_json::from_str(&response_text).expect("Fail while parsing");
            return Ok(cve_json);
        }
    }
    Err(anyhow!("CVE JSON not found for ID: {}", cve_id))
}
