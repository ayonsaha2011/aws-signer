// aws_client.rs

use crate::aws_v4_signer::AwsV4Signer;
use reqwest::{Request, Response};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

pub struct AwsClient {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub service: Option<String>,
    pub region: Option<String>,
    pub cache: HashMap<String, Vec<u8>>,
    pub retries: u32,
    pub init_retry_ms: u64,
}

impl AwsClient {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        service: Option<String>,
        region: Option<String>,
        cache: Option<HashMap<String, Vec<u8>>>,
        retries: Option<u32>,
        init_retry_ms: Option<u64>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            session_token,
            service,
            region,
            cache: cache.unwrap_or_default(),
            retries: retries.unwrap_or(10),
            init_retry_ms: init_retry_ms.unwrap_or(50),
        }
    }

    pub async fn sign(&self, input: &str, init: Option<HashMap<String, String>>) -> Result<Request, Box<dyn std::error::Error>> {
        let mut signer = AwsV4Signer::new(
            init.clone().and_then(|i| i.get("method").cloned()),
            input,
            init.clone(),
            None,
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            self.session_token.clone(),
            self.service.clone(),
            self.region.clone(),
            Some(self.cache.clone()),
            None,
            Some(false),
            Some(false),
            Some(false),
            Some(false),
        )?;

        signer.sign().await
    }

    pub async fn fetch(&self, input: &str, init: Option<HashMap<String, String>>) -> Result<Response, Box<dyn std::error::Error>> {
        for i in 0..=self.retries {
            let request = self.sign(input, init.clone()).await?;
            let fetched = reqwest::Client::new().execute(request).await;

            match fetched {
                Ok(res) if res.status().as_u16() < 500 || res.status().as_u16() == 429 => return Ok(res),
                Ok(_) | Err(_) => {
                    if i == self.retries {
                        return fetched.map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
                    }
                    sleep(Duration::from_millis(self.init_retry_ms * 2u64.pow(i))).await;
                }
            }
        }
        Err("An unknown error occurred, ensure retries is not negative".into())
    }
}
