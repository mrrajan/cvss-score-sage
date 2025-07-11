use std::error::Error;

use crate::cve::{self, ADPcontent, CVEListV5, MetricsWrapper, fetch_cvev5_data};
use crate::tpa::fetch_tpa_data;
use csv::{QuoteStyle, Writer, WriterBuilder};
use log::{error, info};
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ReportHeader {
    pub cve_id: String,
    pub tpa_score: String,
    pub tpa_severity: String,
    pub mismatch_tpa_advisory: String,
    pub mismatch_tpa_cvev5: String,
    pub advisory_content: String,
    pub cve_cna_content: String,
    pub cve_adp_content: String,
}

pub async fn cve_analysis(tpa_baseUrl: &str, tpa_access_token: &str) -> Result<(), Box<dyn Error>> {
    info!("Validation Initiated!");
    let limiter = "50";
    let severity = ["low", "medium", "high", "critical", "null", "none"];
    let mut wrt_ref = WriterBuilder::new()
        .delimiter(b'\t')
        .quote_style(QuoteStyle::Always)
        .from_path("analysis.csv")?;
    for sev in severity {
        let tpa_response = fetch_tpa_data(tpa_baseUrl, sev,limiter, tpa_access_token).await?;
        for item in tpa_response.items {
            let mut cna_summary = "".to_string();
            let mut adp_summary = "".to_string();
            let mut cve_diff = "".to_string();
            let mut adv_diff = "".to_string();
            let cve_id = item.identifier;
            let tpa_severity = item.average_severity;
            let tpa_score = item.average_score;
            let tpa_advisories = item.advisories;
            if let Some(tpa_score) = tpa_score{
            let diff_score = tpa_advisories
                .iter()
                .any(|adv| adv.score.map_or(false, |s| s != tpa_score));
                        let (cve_basescore, cve_data) = retrieve_cve_basescore(&cve_id).await;
            if let Some(basescore) = cve_basescore {
                if tpa_score != basescore {
                    cve_diff = "Yes".to_string();
                }
                if let Some(cve_cna_content) = cve_data.containers.cna.metrics {
                    cna_summary = format_cvss(cve_cna_content).await;
                }
                if let Some(cna_adp_container) = cve_data.containers.adp {
                    for adp_content in cna_adp_container {
                        if let Some(adp) = adp_content.metrics {
                            adp_summary = format_cvss(adp).await;
                        }
                    }
                }
                if diff_score {
                adv_diff = "Yes".to_string();
            }
            }}
            let adv_summary = tpa_advisories
                .iter()
                .map(|adv| {
                    format!(
                        "{};{};{};{}",
                        adv.labels.adv_type,
                        adv.identifier,
                        adv.score
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "N/A".to_string()),
                        adv.severity.clone().unwrap_or_else(|| "N/A".to_string())
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ");
            
            let _ = wrt_ref.serialize(ReportHeader {
                cve_id: cve_id.to_string(),
                tpa_score: tpa_score.unwrap_or_else(|| 0.0).to_string(),
                tpa_severity: tpa_severity.unwrap_or_else(|| "UNKNOWN".to_string()),
                mismatch_tpa_advisory: adv_diff.to_string(),
                mismatch_tpa_cvev5: cve_diff.to_string(),
                advisory_content: adv_summary.to_string(),
                cve_cna_content: cna_summary,
                cve_adp_content: adp_summary,
            });
        }
    }
    wrt_ref.flush()?;
    info!("Validation Done!");
    Ok(())
}

pub async fn retrieve_cve_basescore(cve_id: &str) -> (Option<f32>, CVEListV5) {
    let cve_response = fetch_cvev5_data(cve_id).await.unwrap();
    let mut base_score: Option<f32> = None;
    if let Some(cve_res) = &cve_response.containers.cna.metrics {
        if let Some(score) = cve_v5_metric(cve_res).await {
            base_score = Some(score);
        }
    } else if let Some(adp_container) = &cve_response.containers.adp {
        for adp_content in adp_container {
            if let Some(adp_metrics) = &adp_content.metrics {
                if let Some(adp_score) = cve_v5_metric(&adp_metrics).await {
                    base_score = Some(adp_score);
                    break;
                }
            }
        }
    }
    (base_score, cve_response)
}

pub async fn cve_v5_metric(metric_wrapper: &Vec<Option<MetricsWrapper>>) -> Option<f32> {
    let collector: Vec<&MetricsWrapper> = metric_wrapper.iter().flatten().collect();
    if let Some(score) = collector.iter().find_map(|metric| match metric {
        MetricsWrapper::CvssV4_0 { cvssV4_0 } => Some(cvssV4_0.baseScore),
        _ => None,
    }) {
        return Some(score);
    }
    if let Some(score) = collector.iter().find_map(|metric| match metric {
        MetricsWrapper::CvssV3_1 { cvssV3_1 } => Some(cvssV3_1.baseScore),
        _ => None,
    }) {
        return Some(score);
    }
    if let Some(score) = collector.iter().find_map(|metric| match metric {
        MetricsWrapper::CvssV3_0 { cvssV3_0 } => Some(cvssV3_0.baseScore),
        _ => None,
    }) {
        return Some(score);
    }
    None
}

pub async fn format_cvss(metric_wrapper: Vec<Option<MetricsWrapper>>) -> String {
    metric_wrapper
        .iter()
        .flatten()
        .filter_map(|metric| match metric {
            MetricsWrapper::CvssV4_0 { cvssV4_0 } => Some(format!(
                "V4.0;{};{}",
                cvssV4_0.baseScore, cvssV4_0.baseSeverity
            )),
            MetricsWrapper::CvssV3_1 { cvssV3_1 } => Some(format!(
                "V3.1;{};{}",
                cvssV3_1.baseScore, cvssV3_1.baseSeverity
            )),
            MetricsWrapper::CvssV3_0 { cvssV3_0 } => Some(format!(
                "V3.0;{};{}",
                cvssV3_0.baseScore, cvssV3_0.baseSeverity
            )),
            MetricsWrapper::CvssV2_0 { .. } => None,
            MetricsWrapper::Other { .. } => None,
        })
        .collect::<Vec<_>>()
        .join(" | ")
}
