
# aws_signer

`aws_signer` is a Rust library that implements AWS Signature Version 4 signing for making authenticated requests to AWS services, including generating presigned URLs. This library is compatible with Cloudflare Workers and Cloudflare R2, allowing you to sign HTTP requests in a way that AWS and Cloudflare can verify, ensuring secure communication.

## Features

- AWS Signature Version 4 signing for HTTP requests
- Support for presigned URL generation for temporary access
- Compatible with Cloudflare Workers and Cloudflare R2
- Flexible configuration for AWS credentials and regions
- Designed to integrate easily with `reqwest` for HTTP requests

## Installation

To use the `aws_signer` library in your Rust project, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
aws_signer = "0.1"
```

## Usage

### Setting Up the Client

To create a new AWS client with your credentials, use the `AwsClient::new` function:

```rust
use aws_signer::{AwsClient, AwsOptions, AwsRequestInit};

fn main() {
    let client = AwsClient::new(
        "your_access_key_id".to_string(),
        "your_secret_access_key".to_string(),
        None, // Optional session token if required
        None, // Service will be guessed if None
        None, // Region will be guessed if None
        None,
        Some(3), // Retries
        Some(100), // Initial retry delay in ms
    );

    // Use the client to sign requests or fetch data
}
```

### Signing a Request

You can sign an HTTP request using the `sign` method of `AwsClient`. This example shows how to sign a request using the `reqwest` crate:

```rust
use aws_signer::{AwsClient, AwsRequestInit};
use reqwest::{Request, Method, Url};

#[tokio::main]
async fn main() {
    let client = AwsClient::new(
        "your_access_key_id".to_string(),
        "your_secret_access_key".to_string(),
        None, // Optional session token if required
        None, // Service will be guessed if None
        None, // Region will be guessed if None
        None,
        Some(3), // Retries
        Some(100), // Initial retry delay in ms
    );

    let request = Request::new(
        Method::PUT,
        Url::parse("https://your-bucket.your-account.r2.cloudflarestorage.com/test-file").unwrap(),
    );

    match client.fetch(request, None).await {
        Ok(response) => {
            println!("Response: {:?}", response.text().await.unwrap());
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
```

### Generating a Presigned URL

To generate a presigned URL for a temporary upload to S3 or another AWS service:

```rust
use aws_signer::{AwsClient, AwsOptions, AwsRequestInit};
use reqwest::{Request, Method, Url};

#[tokio::main]
async fn main() {
    let client = AwsClient::new(
        "your_access_key_id".to_string(),
        "your_secret_access_key".to_string(),
        None, // Optional session token if required
        Some("s3".to_string()), // Specify the service
        Some("us-east-1".to_string()), // Specify the region
        None,
        Some(3),
        Some(100),
    );

    let request = Request::new(
        Method::PUT,
        Url::parse("https://your-bucket.s3.amazonaws.com/your-object-key").unwrap(),
    );

    match client.sign(request, None).await {
        Ok(signed_request) => {
            println!("Presigned URL: {}", signed_request.url());
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
```

### Configuration

The library provides flexible configuration options through the `AwsOptions` struct. You can customize the signing process, service, region, and more:

- `access_key_id`: AWS access key ID
- `secret_access_key`: AWS secret access key
- `session_token`: Optional session token for temporary credentials
- `service`: AWS service name (e.g., "s3", "execute-api")
- `region`: AWS region (e.g., "us-east-1")
- `datetime`: Custom datetime for signing
- `sign_query`: Boolean flag to indicate if query should be signed
- `append_session_token`: Boolean flag to append session token

## Compatibility

- **Cloudflare Workers**: This library can be used within Cloudflare Workers to sign requests, making it suitable for serverless environments.
- **Cloudflare R2**: Supports signing requests for Cloudflare R2 storage, making it easy to integrate with Cloudflare's object storage solution.

## Contributing

Contributions are welcome! Please submit issues or pull requests to help improve the library.

## Support

Maintaining this library takes time and effort. If you find it useful, please consider supporting its development:

- **[Buy Me a Coffee](https://www.buymeacoffee.com/ayonsaha2011)**: A small donation helps keep the project alive!
- **[PayPal](https://www.paypal.me/ayonsaha2011)**: One-time donations are appreciated.
- **[Patreon](https://www.patreon.com/ayonsaha2011)**: Become a supporter and get exclusive updates!

Your support will help in continuous development, maintenance, and adding new features to this library. Thank you!

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Based on AWS Signature Version 4 signing process
- Inspired by similar libraries in other languages
