// utils.rs

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use url::{Url, ParseError};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use lazy_static::lazy_static;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

// Define a set of characters to encode as per RFC3986
const FRAGMENT: &AsciiSet = &CONTROLS.add(b'!').add(b'\'').add(b'(').add(b')').add(b'*');

// Utility function to encode a string as per RFC3986
pub fn encode_rfc3986(input: &str) -> String {
    utf8_percent_encode(input, FRAGMENT).to_string()
}

// Utility function to convert a buffer to a hexadecimal string
pub fn buf2hex(buffer: &[u8]) -> String {
    buffer.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// Utility function to decode URL component, similar to decodeURIComponent in JavaScript
pub fn decode_url_component(input: &str) -> Result<String, ParseError> {
    percent_decode_str(input)
        .decode_utf8()
        .map(|s| s.to_string())
        .map_err(|_| ParseError::IdnaError) // Convert Utf8Error to a suitable ParseError variant
}

// Define UNSIGNABLE_HEADERS as a HashSet
lazy_static! {
    pub static ref UNSIGNABLE_HEADERS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("authorization");
        set.insert("content-type");
        set.insert("content-length");
        set.insert("user-agent");
        set.insert("presigned-expires");
        set.insert("expect");
        set.insert("x-amzn-trace-id");
        set.insert("range");
        set.insert("connection");
        set
    };
}

// HMAC SHA-256 hashing function
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// SHA-256 hashing function
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Function to guess the service and region from the URL and headers
pub fn guess_service_region(url: &Url, headers: &HashMap<String, String>) -> (String, String) {
    let hostname = url.host_str().unwrap_or("");
    let pathname = url.path();

    if hostname.ends_with(".on.aws") {
        if let Some(caps) = hostname.split('.').nth(0) {
            return ("lambda".to_string(), caps.to_string());
        }
    } else if hostname.ends_with(".r2.cloudflarestorage.com") {
        return ("s3".to_string(), "auto".to_string());
    } else if hostname.ends_with(".backblazeb2.com") {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() > 2 && parts[1] == "s3" {
            return ("s3".to_string(), parts[2].to_string());
        }
    }

    let modified_hostname = hostname.replace("dualstack.", "");
    let parts: Vec<&str> = modified_hostname.split('.').collect();
    let mut service = parts.get(0).unwrap_or(&"").to_string();
    let mut region = parts.get(1).unwrap_or(&"").to_string();

    if region == "us-gov" {
        region = "us-gov-west-1".to_string();
    } else if region == "s3" || region == "s3-accelerate" {
        region = "us-east-1".to_string();
        service = "s3".to_string();
    } else if service == "iot" {
        if hostname.starts_with("iot.") {
            service = "execute-api".to_string();
        } else if hostname.starts_with("data.jobs.iot.") {
            service = "iot-jobs-data".to_string();
        } else {
            service = if pathname == "/mqtt" {
                "iotdevicegateway".to_string()
            } else {
                "iotdata".to_string()
            };
        }
    } else if service == "autoscaling" {
        let default_value = "".to_string();
        let target_prefix = headers.get("X-Amz-Target").unwrap_or(&default_value);
        if target_prefix.starts_with("AnyScaleFrontendService") {
            service = "application-autoscaling".to_string();
        } else if target_prefix.starts_with("AnyScaleScalingPlannerFrontendService") {
            service = "autoscaling-plans".to_string();
        }
    } else if region.is_empty() && service.starts_with("s3-") {
        region = service[3..].replace("fips-", "").replace("external-1", "").to_string();
        service = "s3".to_string();
    } else if service.ends_with("-fips") {
        service = service[..service.len()-5].to_string();
    }

    (service, region)
}
