// SPDX-License-Identifier: MulanPSL-2.0

//! In-memory core for Robonix user identity, preferences, and access control.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

/// A user known to Robonix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub voiceprint_id: Option<String>,
    pub created_unix: f64,
}

/// Global switches controlling whether input must be authenticated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub text_auth_required: bool,
    pub voice_auth_required: bool,
    pub voice_min_confidence: f32,
    pub allow_voice_fallback: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            text_auth_required: false,
            voice_auth_required: false,
            voice_min_confidence: 0.75,
            allow_voice_fallback: false,
        }
    }
}

/// Access settings and roles associated with one user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccess {
    pub user_id: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub allow_text: bool,
    pub allow_voice: bool,
    pub voice_id: Option<String>,
    pub roles: Vec<String>,
}

/// Authentication information suitable for a task context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthInfo {
    pub verified: bool,
    pub method: String,
    pub user_id: String,
    pub voice_id: Option<String>,
    pub confidence: f32,
}

/// Result returned by an authorization check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Authorization {
    pub allow: bool,
    pub reason: String,
    pub auth: AuthInfo,
}

/// Errors returned by Keystone's in-memory operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeystoneError {
    #[error("user name must not be empty")]
    EmptyUserName,
    #[error("voiceprint ID must not be empty")]
    EmptyVoiceprintId,
    #[error("user '{0}' does not exist")]
    UserNotFound(String),
    #[error("voiceprint '{voiceprint_id}' is already bound to user '{user_id}'")]
    VoiceprintAlreadyBound {
        voiceprint_id: String,
        user_id: String,
    },
}

/// Mutable in-memory Keystone state.
#[derive(Debug, Default)]
pub struct Keystone {
    security: SecurityConfig,
    users: BTreeMap<String, User>,
    configs: BTreeMap<String, Value>,
    access: BTreeMap<String, UserAccess>,
    voiceprints: BTreeMap<String, String>,
}

impl Keystone {
    /// Create an empty store with the supplied global security settings.
    pub fn new(security: SecurityConfig) -> Self {
        Self {
            security,
            ..Self::default()
        }
    }

    /// Replace the global security settings used by subsequent checks.
    pub fn set_security_config(&mut self, security: SecurityConfig) {
        self.security = security;
    }

    /// Return the active global security settings.
    pub fn security_config(&self) -> &SecurityConfig {
        &self.security
    }

    /// Create a user and return its stable generated ID.
    ///
    /// The caller supplies the creation timestamp so a future Chronos
    /// integration can provide the canonical system time.
    pub fn create_user(
        &mut self,
        name: impl Into<String>,
        created_unix: f64,
    ) -> Result<String, KeystoneError> {
        let name = name.into().trim().to_owned();
        if name.is_empty() {
            return Err(KeystoneError::EmptyUserName);
        }
        let id = format!("user_{}", Uuid::new_v4().simple());
        self.users.insert(
            id.clone(),
            User {
                id: id.clone(),
                name,
                voiceprint_id: None,
                created_unix,
            },
        );
        Ok(id)
    }

    /// Return all users in stable ID order.
    pub fn list_users(&self) -> Vec<&User> {
        self.users.values().collect()
    }

    /// Return one user by ID.
    pub fn get_user(&self, user_id: &str) -> Option<&User> {
        self.users.get(user_id)
    }

    /// Delete a user and all preferences, access settings, and voice bindings.
    pub fn delete_user(&mut self, user_id: &str) -> bool {
        let Some(user) = self.users.remove(user_id) else {
            return false;
        };
        if let Some(voiceprint_id) = user.voiceprint_id {
            self.voiceprints.remove(&voiceprint_id);
        }
        self.configs.remove(user_id);
        self.access.remove(user_id);
        true
    }

    /// Bind one voiceprint ID to a user, replacing that user's old binding.
    ///
    /// A voiceprint cannot identify two users. Attempting to reassign an ID
    /// already owned by another user returns an error and leaves state intact.
    pub fn bind_voiceprint(
        &mut self,
        user_id: &str,
        voiceprint_id: impl Into<String>,
    ) -> Result<(), KeystoneError> {
        let voiceprint_id = voiceprint_id.into().trim().to_owned();
        if voiceprint_id.is_empty() {
            return Err(KeystoneError::EmptyVoiceprintId);
        }
        if let Some(owner) = self.voiceprints.get(&voiceprint_id)
            && owner != user_id
        {
            return Err(KeystoneError::VoiceprintAlreadyBound {
                voiceprint_id,
                user_id: owner.clone(),
            });
        }
        let user = self
            .users
            .get_mut(user_id)
            .ok_or_else(|| KeystoneError::UserNotFound(user_id.to_owned()))?;
        if let Some(old_id) = user.voiceprint_id.replace(voiceprint_id.clone()) {
            self.voiceprints.remove(&old_id);
        }
        self.voiceprints.insert(voiceprint_id, user_id.to_owned());
        Ok(())
    }

    /// Resolve the Keystone user bound to a voiceprint service result.
    pub fn identify_user_by_voiceprint(&self, voiceprint_id: &str) -> Option<&User> {
        self.voiceprints
            .get(voiceprint_id)
            .and_then(|user_id| self.users.get(user_id))
    }

    /// Store a user's JSON preference document.
    pub fn set_config(&mut self, user_id: &str, config: Value) -> Result<(), KeystoneError> {
        if !self.users.contains_key(user_id) {
            return Err(KeystoneError::UserNotFound(user_id.to_owned()));
        }
        self.configs.insert(user_id.to_owned(), config);
        Ok(())
    }

    /// Return a user's JSON preference document when one has been set.
    pub fn get_config(&self, user_id: &str) -> Option<&Value> {
        self.configs.get(user_id)
    }

    /// Store access settings for an existing user.
    pub fn set_user_access(&mut self, access: UserAccess) -> Result<(), KeystoneError> {
        if !self.users.contains_key(&access.user_id) {
            return Err(KeystoneError::UserNotFound(access.user_id));
        }
        self.access.insert(access.user_id.clone(), access);
        Ok(())
    }

    /// Return access settings for one user.
    pub fn get_user_access(&self, user_id: &str) -> Option<&UserAccess> {
        self.access.get(user_id)
    }

    /// Authorize a text request according to the current security settings.
    ///
    /// When the global gate or text authentication is disabled, input passes
    /// through without claiming verified identity. When required, the user
    /// must exist and have an enabled access entry with `allow_text` set.
    pub fn authorize_text(&self, user_id: &str) -> Authorization {
        if !self.security.enabled || !self.security.text_auth_required {
            return self.text_authorization(
                user_id,
                true,
                false,
                "text authentication is not required",
            );
        }
        if !self.users.contains_key(user_id) {
            return self.text_authorization(user_id, false, false, "user does not exist");
        }
        let Some(access) = self.access.get(user_id) else {
            return self.text_authorization(user_id, false, false, "user has no access entry");
        };
        if !access.enabled {
            return self.text_authorization(user_id, false, false, "user is disabled");
        }
        if !access.allow_text {
            return self.text_authorization(user_id, false, false, "text access is disabled");
        }
        self.text_authorization(user_id, true, true, "text access allowed")
    }

    /// Build a consistent text authorization response.
    fn text_authorization(
        &self,
        user_id: &str,
        allow: bool,
        verified: bool,
        reason: &str,
    ) -> Authorization {
        Authorization {
            allow,
            reason: reason.to_owned(),
            auth: AuthInfo {
                verified,
                method: "text".to_owned(),
                user_id: user_id.to_owned(),
                voice_id: None,
                confidence: 0.0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn required_text_security() -> SecurityConfig {
        SecurityConfig {
            enabled: true,
            text_auth_required: true,
            ..SecurityConfig::default()
        }
    }

    fn allowed_access(user_id: &str) -> UserAccess {
        UserAccess {
            user_id: user_id.to_owned(),
            display_name: Some("Operator".to_owned()),
            enabled: true,
            allow_text: true,
            allow_voice: true,
            voice_id: None,
            roles: vec!["operator".to_owned()],
        }
    }

    #[test]
    fn creates_lists_and_deletes_users_with_related_state() {
        let mut keystone = Keystone::default();
        let user_id = keystone.create_user("Ada", 42.0).unwrap();
        keystone
            .set_config(&user_id, json!({"locale": "en"}))
            .unwrap();
        keystone.set_user_access(allowed_access(&user_id)).unwrap();
        keystone.bind_voiceprint(&user_id, "voice-1").unwrap();

        assert_eq!(keystone.list_users().len(), 1);
        assert_eq!(keystone.get_user(&user_id).unwrap().name, "Ada");
        assert!(keystone.delete_user(&user_id));
        assert!(keystone.get_config(&user_id).is_none());
        assert!(keystone.get_user_access(&user_id).is_none());
        assert!(keystone.identify_user_by_voiceprint("voice-1").is_none());
    }

    #[test]
    fn rejects_reusing_a_voiceprint_for_another_user() {
        let mut keystone = Keystone::default();
        let first = keystone.create_user("Ada", 1.0).unwrap();
        let second = keystone.create_user("Grace", 2.0).unwrap();
        keystone.bind_voiceprint(&first, "voice-1").unwrap();

        let error = keystone.bind_voiceprint(&second, "voice-1").unwrap_err();
        assert!(matches!(
            error,
            KeystoneError::VoiceprintAlreadyBound { .. }
        ));
        assert_eq!(
            keystone.identify_user_by_voiceprint("voice-1").unwrap().id,
            first
        );
    }

    #[test]
    fn rejects_empty_voiceprint_ids() {
        let mut keystone = Keystone::default();
        let user_id = keystone.create_user("Ada", 1.0).unwrap();

        let error = keystone.bind_voiceprint(&user_id, "  ").unwrap_err();

        assert_eq!(error, KeystoneError::EmptyVoiceprintId);
    }

    #[test]
    fn round_trips_json_preferences() {
        let mut keystone = Keystone::default();
        let user_id = keystone.create_user("Ada", 1.0).unwrap();
        let config = json!({"language": "zh-CN", "speech_rate": 1.1});

        keystone.set_config(&user_id, config.clone()).unwrap();

        assert_eq!(keystone.get_config(&user_id), Some(&config));
    }

    #[test]
    fn required_text_auth_checks_user_access() {
        let mut keystone = Keystone::new(required_text_security());
        let user_id = keystone.create_user("Ada", 1.0).unwrap();

        assert!(!keystone.authorize_text("missing").allow);
        assert!(!keystone.authorize_text(&user_id).allow);

        keystone.set_user_access(allowed_access(&user_id)).unwrap();
        let result = keystone.authorize_text(&user_id);
        assert!(result.allow);
        assert!(result.auth.verified);
        assert_eq!(result.auth.user_id, user_id);
    }

    #[test]
    fn disabled_text_auth_passes_without_claiming_identity() {
        let keystone = Keystone::default();

        let result = keystone.authorize_text("anonymous");

        assert!(result.allow);
        assert!(!result.auth.verified);
    }
}
