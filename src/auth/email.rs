//! Sending the magic link.
//!
//! Two modes. `resend` posts to the Resend HTTP API; `console` writes the link
//! to the log instead of sending anything, which is what makes a first run —
//! and `tests/smoke_test.sh` — work with no mail provider and no credentials.
//!
//! Console mode is not a stub to be replaced later: a single-operator local
//! install is a real deployment shape, and reading your own log is a
//! reasonable way to sign in to it.

use crate::config::EmailConfig;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The link was handed to a mail provider.
    Sent,
    /// The link was written to the log for the operator to copy.
    Logged,
}

pub struct Mailer {
    client: reqwest::Client,
    config: EmailConfig,
    /// Used in the subject line; comes from `[auth].product_name`.
    product_name: String,
    /// Quoted in the body so the reader knows how long they have.
    ttl_secs: i64,
}

/// Hand-written so a derived `Debug` cannot print the Resend key.
impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mailer")
            .field("mode", &self.config.mode)
            .field("from", &self.config.from_header())
            .field(
                "api_key",
                &self.config.resolve_api_key().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Mailer {
    pub fn new(config: EmailConfig, product_name: String, ttl_secs: i64) -> AppResult<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            config,
            product_name,
            ttl_secs,
        })
    }

    /// Whether this mailer will actually deliver mail.
    pub fn sends_mail(&self) -> bool {
        self.config.sends_mail()
    }

    pub fn describe(&self) -> String {
        if self.sends_mail() {
            let from = self.config.from_address.trim();
            if from.is_empty() {
                "resend, but [email].from_address is unset — sending will fail".to_string()
            } else {
                format!("resend, from {}", self.config.from_header())
            }
        } else if self.config.mode.trim().eq_ignore_ascii_case("resend") {
            format!(
                "resend configured but no API key — set [email].api_key or the {} env var; \
                 falling back to the log",
                self.config.api_key_env
            )
        } else {
            "console — sign-in links are written to the log".to_string()
        }
    }

    /// Send a sign-in link, or log it.
    ///
    /// Delivery failure is an error the caller surfaces, but the *reason* is
    /// deliberately not shown to whoever typed the address: it would confirm
    /// whether that address exists here.
    pub async fn send_login_link(&self, email: &str, link: &str) -> AppResult<Delivery> {
        if !self.sends_mail() {
            // A link is a bearer credential, so this is a deliberate decision
            // to write one to the log — hence `warn`, not `info`.
            tracing::warn!(
                email,
                "sign-in link (console mode; treat this as a password): {link}"
            );
            return Ok(Delivery::Logged);
        }

        let key = self
            .config
            .resolve_api_key()
            .ok_or_else(|| AppError::internal("no email API key"))?;
        if self.config.from_address.trim().is_empty() {
            return Err(AppError::bad_request(
                "[email].from_address is required when mode = \"resend\", and must be a sender \
                 you have verified with the provider",
            ));
        }
        let from = self.config.from_header();

        let response = self
            .client
            .post("https://api.resend.com/emails")
            .bearer_auth(key)
            .json(&serde_json::json!({
                "from": from,
                "to": [email],
                "subject": format!("Sign in to {}", self.product_name),
                "text": text_body(&self.product_name, link, self.ttl_secs),
                "html": html_body(&self.product_name, link, self.ttl_secs),
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let detail: String = response
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect();
            return Err(AppError::internal(format!(
                "the mail provider returned {status}: {detail}"
            )));
        }
        Ok(Delivery::Sent)
    }
}

fn minutes(ttl_secs: i64) -> i64 {
    (ttl_secs / 60).max(1)
}

fn text_body(product: &str, link: &str, ttl_secs: i64) -> String {
    format!(
        "Sign in to {product}\n\n\
         Open this link to sign in. It works once and expires in {} minutes.\n\n\
         {link}\n\n\
         If you did not ask to sign in, ignore this message — nothing has changed.\n",
        minutes(ttl_secs)
    )
}

fn html_body(product: &str, link: &str, ttl_secs: i64) -> String {
    // The link is generated by us and is URL-safe hex, but escaping the
    // interpolations costs nothing and keeps this safe if that ever changes.
    format!(
        "<p>Sign in to <strong>{}</strong></p>\
         <p><a href=\"{}\">Click here to sign in</a></p>\
         <p>The link works once and expires in {} minutes. \
         If you did not ask to sign in, ignore this message.</p>",
        escape(product),
        escape(link),
        minutes(ttl_secs)
    )
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: &str, key: Option<&str>) -> EmailConfig {
        EmailConfig {
            mode: mode.into(),
            api_key: key.unwrap_or("").to_string(),
            api_key_env: "QM_TEST_EMAIL_KEY_ABSENT".into(),
            from_address: "qm@acme.test".into(),
            from_name: "QM".into(),
        }
    }

    fn mailer(mode: &str, key: Option<&str>) -> Mailer {
        Mailer::new(config(mode, key), "QM".into(), 900).unwrap()
    }

    #[tokio::test]
    async fn console_mode_logs_the_link_rather_than_sending() {
        let mailer = mailer("console", None);
        assert!(!mailer.sends_mail());
        assert_eq!(
            mailer
                .send_login_link(
                    "ada@acme.test",
                    "http://localhost:8080/auth/callback?token=x"
                )
                .await
                .unwrap(),
            Delivery::Logged
        );
        assert!(mailer.describe().contains("console"));
    }

    #[tokio::test]
    async fn resend_without_a_key_falls_back_to_logging_rather_than_failing_sign_in() {
        let mailer = mailer("resend", None);
        assert!(!mailer.sends_mail());
        assert_eq!(
            mailer
                .send_login_link("ada@acme.test", "http://x/y")
                .await
                .unwrap(),
            Delivery::Logged
        );
        assert!(mailer.describe().contains("no API key"));
    }

    #[test]
    fn a_configured_resend_mailer_reports_that_it_sends() {
        let mailer = mailer("resend", Some("re_test"));
        assert!(mailer.sends_mail());
        assert!(mailer.describe().contains("qm@acme.test"));
    }

    #[test]
    fn debug_never_prints_the_api_key() {
        let mailer = mailer("resend", Some("re_supersecret"));
        let rendered = format!("{mailer:?}");
        assert!(!rendered.contains("re_supersecret"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn bodies_carry_the_link_and_the_expiry() {
        let text = text_body("QM", "http://localhost/auth/callback?token=abc", 900);
        assert!(text.contains("http://localhost/auth/callback?token=abc"));
        assert!(text.contains("15 minutes"));
        assert!(text.contains("works once"));

        let html = html_body("QM", "http://localhost/x", 900);
        assert!(html.contains("href=\"http://localhost/x\""));
    }

    #[test]
    fn html_interpolations_are_escaped() {
        let html = html_body("Acme <script>", "http://x/?a=1&b=2", 900);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("a=1&amp;b=2"));
    }

    #[test]
    fn a_very_short_ttl_still_reads_as_at_least_a_minute() {
        assert!(text_body("QM", "http://x", 30).contains("1 minutes"));
    }
}
