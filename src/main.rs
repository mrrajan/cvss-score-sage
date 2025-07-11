mod analysis;
mod cve;
mod tpa;
use simplelog::*;
#[tokio::main]
async fn main() {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            std::fs::File::create("sage.log").unwrap(),
        ),
    ])
    .unwrap();
    let tpa_baseurl = "<TPA_BaseURL>";
    let tpa_access_token = "Access Token";
    let _ = analysis::cve_analysis(tpa_baseurl, tpa_access_token).await;
}
