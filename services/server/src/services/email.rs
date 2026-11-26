use async_trait::async_trait;
use reqwest::StatusCode;
use std::time::Duration;
use tokio::time::timeout;

use crate::marketing_consent::email::EmailAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailError {
    Auth,
    RateLimited,
    Rejected,
    Transport,
    Timeout,
}

pub struct OutboundEmail {
    pub to: EmailAddress,
    pub subject: String,
    pub text: String,
    pub tag: &'static str,
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError>;
}

pub struct LogEmailSender;

#[async_trait]
impl EmailSender for LogEmailSender {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError> {
        tracing::info!(to = %message.to.masked(), tag = message.tag, "marketing consent email logged");
        Ok(())
    }
}

pub struct ProviderEmailSender {
    pub client: reqwest::Client,
    pub base_url: String,
    pub api_key: String,
    pub from_address: String,
    pub from_name: String,
}

#[async_trait]
impl EmailSender for ProviderEmailSender {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError> {
        let body = serde_json::json!({"personalizations":[{"to":[{"email":message.to.expose()}]}],"from":{"email":self.from_address,"name":self.from_name},"subject":message.subject,"content":[{"type":"text/plain","value":message.text}]});
        let request = self
            .client
            .post(format!(
                "{}/v3/mail/send",
                self.base_url.trim_end_matches('/')
            ))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send();
        let response = timeout(Duration::from_secs(10), request)
            .await
            .map_err(|_| EmailError::Timeout)?
            .map_err(|_| EmailError::Transport)?;
        match response.status() {
            status if status.is_success() => Ok(()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(EmailError::Auth),
            StatusCode::TOO_MANY_REQUESTS => Err(EmailError::RateLimited),
            status if status.is_client_error() => Err(EmailError::Rejected),
            _ => Err(EmailError::Transport),
        }
    }
}
