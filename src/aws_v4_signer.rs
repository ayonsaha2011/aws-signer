// aws_v4_signer.rs

use crate::utils::{encode_rfc3986, buf2hex, decode_url_component, hmac_sha256, sha256_hash, UNSIGNABLE_HEADERS, guess_service_region};
use chrono::{Utc, DateTime};
use std::collections::{HashMap, HashSet};
use url::Url;
use reqwest::{Request, header::HeaderMap, header::HeaderName, header::HeaderValue, Method};

#[derive(Debug)]
pub struct AwsV4Signer {
    pub method: String,
    pub url: Url,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub service: String,
    pub region: String,
    pub cache: HashMap<String, Vec<u8>>,
    pub datetime: String,
    pub sign_query: bool,
    pub append_session_token: bool,
    pub all_headers: bool,
    pub single_encode: bool,
    pub signable_headers: Vec<String>,
    pub signed_headers: String,
    pub canonical_headers: String,
    pub credential_string: String,
    pub encoded_path: String,
    pub encoded_search: String,
}

impl AwsV4Signer {
    pub fn new(
        method: Option<String>,
        url: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        service: Option<String>,
        region: Option<String>,
        cache: Option<HashMap<String, Vec<u8>>>,
        datetime: Option<String>,
        sign_query: Option<bool>,
        append_session_token: Option<bool>,
        all_headers: Option<bool>,
        single_encode: Option<bool>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if url.is_empty() {
            return Err("url is a required option".into());
        }
        if access_key_id.is_empty() {
            return Err("accessKeyId is a required option".into());
        }
        if secret_access_key.is_empty() {
            return Err("secretAccessKey is a required option".into());
        }

        let method = method.unwrap_or_else(|| if body.is_some() { "POST".to_string() } else { "GET".to_string() });
        let url = Url::parse(url)?;
        let mut headers = headers.unwrap_or_else(HashMap::new);
        let cache = cache.unwrap_or_else(HashMap::new);

        let (guessed_service, guessed_region) = if service.is_none() || region.is_none() {
            guess_service_region(&url, &headers)
        } else {
            (service.clone().unwrap_or_default(), region.clone().unwrap_or_default())
        };

        let service = service.or(Some(guessed_service)).unwrap_or_else(|| "s3".to_string());
        let region = region.or(Some(guessed_region)).unwrap_or_else(|| "auto".to_string());

        let datetime = datetime.unwrap_or_else(|| {
            let now: DateTime<Utc> = Utc::now();
            now.format("%Y%m%dT%H%M%SZ").to_string()
        });

        let sign_query = sign_query.unwrap_or(false);
        let append_session_token = append_session_token.unwrap_or(service == "iotdevicegateway");
        let all_headers = all_headers.unwrap_or(false);
        let single_encode = single_encode.unwrap_or(false);

        headers.remove("Host");
        if service == "s3" && !sign_query && !headers.contains_key("X-Amz-Content-Sha256") {
            headers.insert("X-Amz-Content-Sha256".to_string(), "UNSIGNED-PAYLOAD".to_string());
        }

        headers.insert("X-Amz-Date".to_string(), datetime.clone());
        if let Some(token) = &session_token {
            if !append_session_token {
                headers.insert("X-Amz-Security-Token".to_string(), token.clone());
            }
        }

        let mut signable_headers: Vec<String> = vec!["host".to_string()];
        signable_headers.extend(headers.keys().cloned().filter(|header| all_headers || !UNSIGNABLE_HEADERS.contains(header.as_str())));
        signable_headers.sort();

        let signed_headers = signable_headers.join(";");

        let canonical_headers = signable_headers.iter()
            .map(|header| format!("{}:{}", header, headers.get(header).unwrap_or(&"".to_string()).trim()))
            .collect::<Vec<String>>()
            .join("\n");

        let credential_string = format!("{}/{}/{}/aws4_request", &datetime[..8], region, service);

        let encoded_path = Self::encode_path(&url, service.as_str(), single_encode);
        let encoded_search = Self::encode_search(&url, service.as_str());

        Ok(AwsV4Signer {
            method,
            url,
            headers,
            body,
            access_key_id,
            secret_access_key,
            session_token,
            service,
            region,
            cache,
            datetime,
            sign_query,
            append_session_token,
            all_headers,
            single_encode,
            signable_headers,
            signed_headers,
            canonical_headers,
            credential_string,
            encoded_path,
            encoded_search,
        })
    }

    pub async fn sign(&mut self) -> Result<Request, Box<dyn std::error::Error>> {
        if self.sign_query {
            self.url.query_pairs_mut().append_pair("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
            self.url.query_pairs_mut().append_pair("X-Amz-Credential", &format!("{}/{}", self.access_key_id, self.credential_string));
            self.url.query_pairs_mut().append_pair("X-Amz-Date", &self.datetime);
            self.url.query_pairs_mut().append_pair("X-Amz-Expires", "86400");
            self.url.query_pairs_mut().append_pair("X-Amz-SignedHeaders", &self.signed_headers);

            let signature = self.signature().await?;
            self.url.query_pairs_mut().append_pair("X-Amz-Signature", &signature);

            if let Some(token) = &self.session_token {
                if self.append_session_token {
                    self.url.query_pairs_mut().append_pair("X-Amz-Security-Token", token);
                }
            }
        } else {
            let auth_header = self.auth_header().await?;
            self.headers.insert("Authorization".to_string(), auth_header);
        }

        let mut req = reqwest::Request::new(
            self.method.parse::<Method>().unwrap_or(Method::GET),
            self.url.clone(),
        );

        let mut header_map = HeaderMap::new();
        for (key, value) in &self.headers {
            header_map.insert(HeaderName::from_bytes(key.as_bytes())?, HeaderValue::from_str(value)?);
        }

        *req.headers_mut() = header_map;

        if let Some(body) = &self.body {
            *req.body_mut() = Some(body.clone().into());
        }

        Ok(req)
    }

    pub async fn auth_header(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let access_key_id = self.access_key_id.clone();
        let credential_string = self.credential_string.clone();
        let signed_headers = self.signed_headers.clone();
        let signature = self.signature().await?;

        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            access_key_id,
            credential_string,
            signed_headers,
            signature
        ))
    }

    pub async fn signature(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let date = &self.datetime[..8];
        let cache_key = format!("{},{},{},{}", self.secret_access_key, date, self.region, self.service);
        let mut k_credentials = self.cache.get(&cache_key).cloned();

        if k_credentials.is_none() {
            let k_date = hmac_sha256(format!("AWS4{}", self.secret_access_key).as_bytes(), date.as_bytes());
            let k_region = hmac_sha256(&k_date, self.region.as_bytes());
            let k_service = hmac_sha256(&k_region, self.service.as_bytes());
            k_credentials = Some(hmac_sha256(&k_service, b"aws4_request"));
            self.cache.insert(cache_key.clone(), k_credentials.clone().unwrap());
        }

        let signature = hmac_sha256(k_credentials.unwrap().as_slice(), self.string_to_sign().await?.as_bytes());
        Ok(buf2hex(&signature))
    }

    pub async fn string_to_sign(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.datetime,
            self.credential_string,
            buf2hex(&sha256_hash(self.canonical_string().await?.as_bytes()))
        ))
    }

    pub async fn canonical_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.method.to_uppercase(),
            self.encoded_path,
            self.encoded_search,
            format!("{}\n", self.canonical_headers),
            self.signed_headers,
            self.hex_body_hash().await?
        ))
    }

    pub async fn hex_body_hash(&self) -> Result<String, Box<dyn std::error::Error>> {
        let hash_header = self.headers.get("X-Amz-Content-Sha256").cloned();
        let hash_value = if let Some(header) = hash_header {
            header
        } else if self.service == "s3" && self.sign_query {
            "UNSIGNED-PAYLOAD".to_string()
        } else {
            if let Some(body) = &self.body {
                buf2hex(&sha256_hash(body.as_bytes()))
            } else {
                buf2hex(&sha256_hash(b""))
            }
        };
        Ok(hash_value)
    }

    pub fn encode_path(url: &Url, service: &str, single_encode: bool) -> String {
        let mut encoded_path = if service == "s3" {
            decode_url_component(url.path()).unwrap_or_else(|_| url.path().to_string())
        } else {
            url.path().replace("//", "/")
        };

        if !single_encode {
            encoded_path = urlencoding::encode(&encoded_path).to_string().replace("%2F", "/");
        }

        encode_rfc3986(&encoded_path)
    }

    pub fn encode_search(url: &Url, service: &str) -> String {
        let mut seen_keys = HashSet::new();
        let mut search_params: Vec<(String, String)> = url.query_pairs()
            .filter(|(k, _)| {
                if k.is_empty() {
                    return false;
                }
                if service == "s3" && seen_keys.contains(k.as_ref()) {
                    return false;
                }
                seen_keys.insert(k.clone());
                true
            })
            .map(|(k, v)| (encode_rfc3986(&urlencoding::encode(&k)), encode_rfc3986(&urlencoding::encode(&v))))
            .collect();

        search_params.sort();

        search_params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join("&")
    }
}
