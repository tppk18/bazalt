use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::{header, HeaderMap};
use base64::Engine;
use parking_lot::Mutex;
use uuid::Uuid;

use crate::config::AuthConfig;

const SESSION_COOKIE: &str = "bazalt_session";
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_FAILURES: u32 = 8;
const MAX_SESSIONS: usize = 4096;

#[derive(Clone)]
pub struct AuthManager {
    cfg: AuthConfig,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    failures: Arc<Mutex<HashMap<IpAddr, LoginFailures>>>,
}

#[derive(Clone, Copy)]
struct LoginFailures {
    window_started: Instant,
    failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginError {
    Forbidden,
    RateLimited,
}

impl AuthManager {
    pub fn new(cfg: AuthConfig) -> Self {
        Self {
            cfg,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            failures: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn login(&self, ip: IpAddr, username: &str, password: &str) -> Result<String, LoginError> {
        if !self.cfg.enabled {
            return Ok(String::new());
        }
        if self.is_rate_limited(ip) {
            return Err(LoginError::RateLimited);
        }
        let valid = constant_time_eq(username.as_bytes(), self.cfg.username.as_bytes())
            & constant_time_eq(password.as_bytes(), self.cfg.password.as_bytes());
        if !valid {
            self.record_failure(ip);
            return Err(LoginError::Forbidden);
        }
        self.failures.lock().remove(&ip);
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, expiry| *expiry > now);
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions.iter().min_by_key(|(_, expiry)| **expiry).map(|(token, _)| token.clone()) {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(token.clone(), now + self.cfg.session_ttl);
        Ok(token)
    }

    pub fn is_authorized(&self, headers: &HeaderMap) -> bool {
        if !self.cfg.enabled {
            return true;
        }
        if self.valid_basic(headers) {
            return true;
        }
        self.session_token(headers)
            .map(|token| self.valid_session(&token))
            .unwrap_or(false)
    }

    pub fn logout(&self, headers: &HeaderMap) {
        if let Some(token) = self.session_token(headers) {
            self.sessions.lock().remove(&token);
        }
    }

    pub fn set_cookie_header(&self, token: &str) -> String {
        let mut value = format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
            self.cfg.session_ttl.as_secs()
        );
        if self.cfg.cookie_secure {
            value.push_str("; Secure");
        }
        value
    }

    pub fn clear_cookie_header(&self) -> String {
        let mut value = format!(
            "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        );
        if self.cfg.cookie_secure {
            value.push_str("; Secure");
        }
        value
    }

    fn valid_basic(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let Some(encoded) = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic ")) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let Some(split) = decoded.iter().position(|b| *b == b':') else {
            return false;
        };
        constant_time_eq(&decoded[..split], self.cfg.username.as_bytes())
            & constant_time_eq(&decoded[split + 1..], self.cfg.password.as_bytes())
    }

    fn session_token(&self, headers: &HeaderMap) -> Option<String> {
        let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
        for item in cookie.split(';') {
            let mut parts = item.trim().splitn(2, '=');
            if parts.next()? == SESSION_COOKIE {
                return parts.next().map(str::to_owned);
            }
        }
        None
    }

    fn valid_session(&self, token: &str) -> bool {
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, expiry| *expiry > now);
        sessions.get(token).is_some_and(|expiry| *expiry > now)
    }

    fn is_rate_limited(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut failures = self.failures.lock();
        failures.retain(|_, state| now.duration_since(state.window_started) < LOGIN_WINDOW);
        failures.get(&ip).is_some_and(|state| state.failures >= LOGIN_MAX_FAILURES)
    }

    fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut failures = self.failures.lock();
        let state = failures.entry(ip).or_insert(LoginFailures { window_started: now, failures: 0 });
        if now.duration_since(state.window_started) >= LOGIN_WINDOW {
            *state = LoginFailures { window_started: now, failures: 1 };
        } else {
            state.failures = state.failures.saturating_add(1);
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    let max = a.len().max(b.len());
    for i in 0..max {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(av ^ bv);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool) -> AuthConfig {
        AuthConfig {
            enabled,
            username: "admin".into(),
            password: "secret".into(),
            session_ttl: Duration::from_secs(3600),
            cookie_secure: false,
        }
    }

    #[test]
    fn login_and_session_work() {
        let auth = AuthManager::new(cfg(true));
        let token = auth.login("127.0.0.1".parse().unwrap(), "admin", "secret").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, format!("{SESSION_COOKIE}={token}").parse().unwrap());
        assert!(auth.is_authorized(&headers));
    }

    #[test]
    fn disabled_auth_accepts_requests() {
        let auth = AuthManager::new(cfg(false));
        assert!(auth.is_authorized(&HeaderMap::new()));
    }
}
