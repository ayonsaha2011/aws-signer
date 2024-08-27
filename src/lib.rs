// src/lib.rs

pub mod aws_signer;
pub mod aws_v4_signer;
pub mod utils;

// You can put shared items here if necessary

#[cfg(test)]
mod tests {
    use crate::aws_v4_signer::AwsV4Signer;

    #[tokio::test]
    async fn it_works() {
        // `https://${bucketName}.${accountId}.r2.cloudflarestorage.com`
        let url = "https://file-upload-service.c956f39d327e48e489a7474b5485ac37.r2.cloudflarestorage.com/tinybird-p1.mkv".to_string();
        let mut client = AwsV4Signer::new(
            Some("PUT".to_string()), // Example method
            &url,
            None, // init
            None, // body
            "b0bbe29497e2c201194c79f35aac8ee8".to_string(),
            "064c0527a32d9e0241c752d754daad354617ba5f458caaf6d5f07db9e4c18438".to_string(),
            None, // session_token
            Some("s3".to_string()),
            Some("auto".to_string()),
            None, // cache
            None, // datetime
            Some(true), // sign_query
            None, // append_session_token
            None, // all_headers
            None, // single_encode
        ).unwrap();

        let signed_request = client.sign().await.unwrap();
        println!("signed_request {:?}", signed_request);
        println!("signed_request url {:?}", signed_request.url().to_string());

    }
}