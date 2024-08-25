
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Request, Response, Url};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

// Type alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Define a custom error type
#[derive(Debug)]
struct AwsError(String);

impl fmt::Display for AwsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for AwsError {}


trait ToUrlString {
    fn to_url_string(&self) -> String;
}

impl ToUrlString for Request {
    fn to_url_string(&self) -> String {
        let mut url = self.url().clone();

        // Extract headers and treat them as query parameters for this example
        let headers = self.headers();

        for (key, value) in headers.iter() {
            // Convert header name and value to strings
            let key_str = key.as_str();
            let value_str = value.to_str().unwrap_or("");

            // Append as query parameters (or handle as needed)
            url.query_pairs_mut().append_pair(key_str, value_str);
        }

        url.to_string()
    }
}

pub struct AwsClient {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    service: Option<String>,
    region: Option<String>,
    cache: HashMap<String, Vec<u8>>,
    retries: usize,
    init_retry_ms: u64,
}

impl AwsClient {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        service: Option<String>,
        region: Option<String>,
        cache: Option<HashMap<String, Vec<u8>>>,
        retries: Option<usize>,
        init_retry_ms: Option<u64>,
    ) -> Self {
        if access_key_id.is_empty() {
            panic!("accessKeyId is a required option");
        }
        if secret_access_key.is_empty() {
            panic!("secretAccessKey is a required option");
        }
        AwsClient {
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

    pub fn default() -> Self {
        AwsClient {
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: None,
            service: None,
            region: None,
            cache: HashMap::new(),
            retries: 10,
            init_retry_ms: 50,
        }
    }

    pub async fn sign(&self, input: Request, init: Option<AwsRequestInit>) -> Result<Request, Box<dyn Error>> {
        let url = input.url().to_string();
        let method = input.method().as_str().to_string();
        let mut headers = input.headers().clone();
        let body = input.body().map(|b| b.as_bytes().unwrap_or_default().to_vec());

        let mut signer = AwsV4Signer::new(
            &method,
            &url,
            headers.clone(),
            body.clone(),
            self.access_key_id.clone(),
            self.secret_access_key.clone(),
            self.session_token.clone(),
            self.service.clone(),
            self.region.clone(),
        );

        signer.sign().await?;

        // Update headers and URL in the request
        headers = signer.headers;
        let url = signer.url;
        let mut req = Request::new(method.parse()?, url);
        *req.headers_mut() = headers;
        if let Some(body) = body {
            *req.body_mut() = Some(body.into());
        }

        Ok(req)
    }

    pub async fn sign_url_string_with_headers(&self, signed_request: Request) -> Result<String, Box<dyn
    Error>> {
        let mut signed_url = signed_request.url().to_string();
        signed_url.push_str("?");
        for (key, value) in signed_request.headers() {
            signed_url.push_str(&format!("{}={}&", key, value.to_str()?));
        }
        signed_url.pop(); // Remove trailing '&'
        Ok(signed_url)
    }

    pub async fn fetch(&self, input: Request, init: Option<AwsRequestInit>) -> Result<Response, Box<dyn Error>> {
        let signed_request = self.sign(input, init).await?;
        let client = Client::new();
        let response = client.execute(signed_request).await?;
        Ok(response)
    }
}

#[derive(Debug)]
pub struct AwsRequestInit {
    aws: Option<AwsOptions>,
}

impl AwsRequestInit {
    pub fn new(aws: Option<AwsOptions>) -> Self {
        AwsRequestInit { aws }
    }

    pub fn default() -> Self {
        AwsRequestInit { aws: None }
    }
}

#[derive(Debug)]
pub struct AwsOptions {
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
    service: Option<String>,
    region: Option<String>,
    datetime: Option<String>,
    sign_query: Option<bool>,
    append_session_token: Option<bool>,
    all_headers: Option<bool>,
    single_encode: Option<bool>,
}

impl AwsOptions {
    pub fn new(
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        session_token: Option<String>,
        service: Option<String>,
        region: Option<String>,
        datetime: Option<String>,
        sign_query: Option<bool>,
        append_session_token: Option<bool>,
        all_headers: Option<bool>,
        single_encode: Option<bool>,
    ) -> Self {
        AwsOptions {
            access_key_id,
            secret_access_key,
            session_token,
            service,
            region,
            datetime,
            sign_query,
            append_session_token,
            all_headers,
            single_encode,
        }
    }

    pub fn default() -> Self {
        AwsOptions {
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            service: None,
            region: None,
            datetime: None,
            sign_query: Some(false),
            append_session_token: Some(false),
            all_headers: Some(false),
            single_encode: Some(true),
        }
    }
}

pub struct AwsV4Signer {
    method: String,
    url: Url,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    service: String,
    region: String,
    datetime: String,
    sign_query: bool,
    append_session_token: bool,
}

impl AwsV4Signer {
    pub fn new(
        method: &str,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        service: Option<String>,
        region: Option<String>,
    ) -> Self {
        let url = Url::parse(url).expect("Invalid URL");
        let datetime = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let (service, region) = if service.is_some() && region.is_some() {
            (service.unwrap(), region.unwrap())
        } else {
            guess_service_region(&url, &headers)
        };

        AwsV4Signer {
            method: method.to_string(),
            url,
            headers,
            body,
            access_key_id,
            secret_access_key,
            session_token,
            service,
            region,
            datetime,
            sign_query: false,
            append_session_token: false,
        }
    }

    pub fn default() -> Self {
        AwsV4Signer {
            method: "GET".to_string(),
            url: Url::parse("http://example.com").unwrap(),
            headers: HeaderMap::new(),
            body: None,
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: None,
            service: "s3".to_string(),
            region: "us-east-1".to_string(),
            datetime: Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
            sign_query: false,
            append_session_token: false,
        }
    }

    pub async fn sign(&mut self) -> Result<(), Box<dyn Error>> {
        if self.sign_query {
            let signature = self.signature().await?;
            self.url.query_pairs_mut().append_pair("X-Amz-Signature", &signature);
            if let Some(token) = &self.session_token {
                if self.append_session_token {
                    self.url.query_pairs_mut().append_pair("X-Amz-Security-Token", token);
                }
            }
        } else {
            let auth_header = self.auth_header().await?;
            self.headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header)?,
            );
        }

        Ok(())
    }

    async fn signature(&self) -> Result<String, Box<dyn Error>> {
        let string_to_sign = self.string_to_sign().await?;
        let date = &self.datetime[..8];
        let signing_key = self.get_signing_key(date);
        let signature = hmac_sha256(&signing_key, string_to_sign.as_bytes());
        Ok(hex::encode(signature))
    }

    async fn auth_header(&self) -> Result<String, Box<dyn Error>> {
        let signature = self.signature().await?;
        let signed_headers = "host;x-amz-date"; // Example; expand as needed
        let credential_scope = format!("{}/{}/{}/aws4_request", &self.datetime[..8], self.region, self.service);
        let authorization_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key_id, credential_scope, signed_headers, signature
        );
        Ok(authorization_header)
    }

    async fn string_to_sign(&self) -> Result<String, Box<dyn Error>> {
        let canonical_request = self.canonical_request().await?;
        let hashed_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let credential_scope = format!("{}/{}/{}/aws4_request", &self.datetime[..8], self.region, self.service);
        Ok(format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.datetime, credential_scope, hashed_request
        ))
    }

    async fn canonical_request(&self) -> Result<String, Box<dyn Error>> {
        let canonical_uri = self.url.path();
        let canonical_query_string = self.url.query().unwrap_or("");
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", self.url.host_str().unwrap(), self.datetime);
        let signed_headers = "host;x-amz-date"; // Example; expand as needed
        let payload_hash = "UNSIGNED-PAYLOAD"; // Use actual payload hash if needed

        Ok(format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.method, canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_hash
        ))
    }

    fn get_signing_key(&self, date: &str) -> Vec<u8> {
        let k_date = hmac_sha256(format!("AWS4{}", self.secret_access_key).as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn guess_service_region(url: &Url, _headers: &HeaderMap) -> (String, String) {
    // Placeholder implementation to mimic guessing logic from JS
    if url.host_str().unwrap_or("").ends_with(".r2.cloudflarestorage.com") {
        ("s3".to_string(), "auto".to_string())
    } else {
        ("".to_string(), "".to_string()) // Replace with actual logic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::{Method, Url};
    use reqwest::header::HeaderMap;

    #[tokio::test]
    async fn test_sign_request() {
        let access_key_id = "test_access_key".to_string();
        let secret_key = "test_secret".to_string();
        let region = "us-east-1".to_string();
        let client = AwsClient::new(
            access_key_id.clone(),
            secret_key.clone(),
            None,
            Some("s3".to_string()),
            Some(region.clone()),
            None,
            None,
            None,
        );

        let url = Url::parse("https://test-bucket.s3.amazonaws.com/test-object").unwrap();
        let request = Request::new(Method::GET, url.clone());

        let signed_request = client.sign(request, None).await.unwrap();
        assert!(signed_request.url().as_str().contains("https://test-bucket.s3.amazonaws.com/test-object"));

        let headers = signed_request.headers();
        assert!(headers.contains_key(AUTHORIZATION));
        let signed_url = signed_request.to_url_string();
        assert!(signed_url.contains(access_key_id.as_str()));
        assert!(signed_url.contains(region.as_str()));
    }

    #[test]
    fn test_guess_service_region() {
        let url = Url::parse("https://example-bucket.r2.cloudflarestorage.com").unwrap();
        let headers = HeaderMap::new();

        let (service, region) = guess_service_region(&url, &headers);

        assert_eq!(service, "s3");
        assert_eq!(region, "auto");
    }
}