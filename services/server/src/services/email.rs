use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use reqwest::{StatusCode, Url};
use zeroize::Zeroizing;

use crate::{
    alerts::{AlertManager, EmailSendFailedAlert},
    marketing_consent::email::EmailAddress,
    observability::{observe_external, record_email_send},
};

const SEND_TIMEOUT: Duration = Duration::from_secs(10);
const VERIFICATION_TAG: &str = "marketing_consent_verification";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailError {
    Auth,
    RateLimited,
    Rejected,
    Transport,
    Timeout,
}

impl EmailError {
    fn outcome(self) -> &'static str {
        match self {
            Self::Auth => "failed_auth",
            Self::RateLimited => "rate_limited",
            Self::Rejected => "failed_rejected",
            Self::Transport => "failed_transport",
            Self::Timeout => "failed_timeout",
        }
    }
}

pub struct OutboundEmail {
    owner: String,
    to: EmailAddress,
    subject: &'static str,
    text: Zeroizing<String>,
    code: Zeroizing<String>,
    tag: &'static str,
}

impl OutboundEmail {
    pub fn verification(owner: String, to: EmailAddress, code: &str) -> Self {
        Self {
            owner,
            to,
            subject: "Confirm your email for Walrus Memory updates",
            text: Zeroizing::new(format!("Your verification code is {code}. It expires in 15 minutes.\n\nIf you didn't ask for this, ignore this email.")),
            code: Zeroizing::new(code.into()),
            tag: VERIFICATION_TAG,
        }
    }
}

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError>;
}

#[derive(Clone, Default, Debug)]
pub enum EmailDelivery {
    #[default]
    Disabled,
    Log,
    Provider(ProviderConfig),
}

#[derive(Clone)]
pub struct ProviderConfig {
    endpoint: Url,
    api_key: Zeroizing<String>,
    from_address: EmailAddress,
    from_name: String,
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderConfig(<redacted>)")
    }
}

impl EmailDelivery {
    pub fn from_env(network: &str) -> Self {
        Self::parse(network, |name| std::env::var(name).ok())
            .unwrap_or_else(|message| panic!("{message}"))
    }

    fn parse(network: &str, read: impl Fn(&str) -> Option<String>) -> Result<Self, &'static str> {
        let value = |name| {
            read(name)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };
        match value("EMAIL_DELIVERY_MODE")
            .as_deref()
            .unwrap_or("disabled")
        {
            "disabled" => Ok(Self::Disabled),
            "log" if !network.eq_ignore_ascii_case("mainnet") => Ok(Self::Log),
            "log" => Err("EMAIL_DELIVERY_MODE=log is forbidden on mainnet"),
            "provider" => {
                let api_key = Zeroizing::new(
                    value("EMAIL_PROVIDER_API_KEY")
                        .ok_or("EMAIL_PROVIDER_API_KEY is required in provider mode")?,
                );
                let from_address = value("EMAIL_FROM_ADDRESS")
                    .as_deref()
                    .and_then(EmailAddress::parse)
                    .ok_or("EMAIL_FROM_ADDRESS must be a valid address in provider mode")?;
                let base =
                    value("EMAIL_API_BASE").unwrap_or_else(|| "https://api.sendgrid.com".into());
                let base =
                    Url::parse(&base).map_err(|_| "EMAIL_API_BASE must be an HTTPS origin")?;
                if base.scheme() != "https"
                    || base.host_str().is_none()
                    || !base.username().is_empty()
                    || base.password().is_some()
                    || base.query().is_some()
                    || base.fragment().is_some()
                    || base.path() != "/"
                {
                    return Err("EMAIL_API_BASE must be an HTTPS origin");
                }
                Ok(Self::Provider(ProviderConfig {
                    endpoint: base.join("v3/mail/send").expect("validated email origin"),
                    api_key,
                    from_address,
                    from_name: value("EMAIL_FROM_NAME").unwrap_or_else(|| "Walrus Memory".into()),
                }))
            }
            _ => Err("EMAIL_DELIVERY_MODE must be disabled, log, or provider"),
        }
    }

    pub fn build(
        &self,
        client: reqwest::Client,
        alerts: Arc<AlertManager>,
        network: &str,
    ) -> Option<Arc<dyn EmailSender>> {
        match self {
            Self::Disabled => None,
            Self::Log => Some(Arc::new(LogEmailSender)),
            Self::Provider(config) => Some(Arc::new(ProviderEmailSender {
                client,
                config: config.clone(),
                alerts,
                network: network.into(),
                timeout: SEND_TIMEOUT,
            })),
        }
    }
}

struct LogEmailSender;

#[async_trait]
impl EmailSender for LogEmailSender {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError> {
        tracing::info!(owner = %message.owner, to = %message.to.masked(), tag = message.tag, code = %message.code.as_str(), "marketing consent email logged");
        record_email_send(message.tag, "logged");
        Ok(())
    }
}

struct ProviderEmailSender {
    client: reqwest::Client,
    config: ProviderConfig,
    alerts: Arc<AlertManager>,
    network: String,
    timeout: Duration,
}

#[async_trait]
impl EmailSender for ProviderEmailSender {
    async fn send(&self, message: OutboundEmail) -> Result<(), EmailError> {
        let start = Instant::now();
        let request = self
            .client
            .post(self.config.endpoint.clone())
            .bearer_auth(self.config.api_key.as_str())
            .json(&serde_json::json!({
                "personalizations": [{"to": [{"email": message.to.expose()}]}],
                "from": {"email": self.config.from_address.expose(), "name": self.config.from_name},
                "subject": message.subject,
                "content": [{"type": "text/plain", "value": message.text.as_str()}],
            }))
            .send();
        let (result, status) = match tokio::time::timeout(self.timeout, request).await {
            Err(_) => (Err(EmailError::Timeout), "timeout".into()),
            Ok(Err(_)) => (Err(EmailError::Transport), "transport".into()),
            Ok(Ok(response)) => {
                let status = response.status();
                let result = match status {
                    status if status.is_success() => Ok(()),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(EmailError::Auth),
                    StatusCode::TOO_MANY_REQUESTS => Err(EmailError::RateLimited),
                    status if status.is_client_error() => Err(EmailError::Rejected),
                    _ => Err(EmailError::Transport),
                };
                (result, status.as_u16().to_string())
            }
        };
        observe_external("email", "send", &status, start.elapsed());
        let outcome = result.err().map_or("sent", EmailError::outcome);
        record_email_send(message.tag, outcome);
        if result.is_err() {
            tracing::warn!(tag = message.tag, outcome, %status, "verification email delivery failed");
            if self
                .alerts
                .notify_email_send_failed(EmailSendFailedAlert {
                    sui_network: &self.network,
                    tag: message.tag,
                    outcome,
                })
                .await
                .is_err()
            {
                tracing::warn!("email delivery failure alert could not be sent");
            }
        }
        result
    }
}

#[cfg(test)]
mod tests;
