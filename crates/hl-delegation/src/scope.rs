//! Scopes (`docs/delegation.md` §3): what a grant allows, as
//! `service:action:resource`, and the concrete action a request names.
//!
//! Matching is exact bytes. Resources are never normalized here: a service's
//! adapter refuses a non-canonical one before it is matched.

use std::fmt;

const SERVICE_MAX: usize = 32;
const ACTION_MAX: usize = 64;
const RESOURCE_MAX: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// Not three `:`-separated parts.
    Shape,
    Service,
    Action,
    Resource,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScopeError::Shape => "not service:action:resource",
            ScopeError::Service => "bad service",
            ScopeError::Action => "bad action",
            ScopeError::Resource => "bad resource",
        })
    }
}

impl std::error::Error for ScopeError {}

/// A service or action segment of a grant scope.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Name {
    Any,
    Is(String),
}

/// A grant scope's resource.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Resource {
    Any,
    Is(String),
    /// `p/*`: anything longer than `p/` that starts with it. Holds `p/`.
    Under(String),
}

/// What a grant allows: a pattern over concrete actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    service: Name,
    action: Name,
    resource: Resource,
}

/// One concrete action, as a request names it: no wildcards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    service: String,
    action: String,
    resource: String,
}

/// Splits at the first two `:`; the resource may hold more.
fn split(s: &str) -> Result<(&str, &str, &str), ScopeError> {
    let (service, rest) = s.split_once(':').ok_or(ScopeError::Shape)?;
    let (action, resource) = rest.split_once(':').ok_or(ScopeError::Shape)?;
    Ok((service, action, resource))
}

fn word_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

fn service_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= SERVICE_MAX && s.chars().all(word_char)
}

fn action_ok(s: &str) -> bool {
    s.len() <= ACTION_MAX
        && s.split('.')
            .all(|p| !p.is_empty() && p.chars().all(word_char))
}

/// Printable ASCII without space or `*`.
fn resource_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= RESOURCE_MAX
        && s.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'*')
}

fn name(s: &str, ok: fn(&str) -> bool, err: ScopeError) -> Result<Name, ScopeError> {
    match s {
        "*" => Ok(Name::Any),
        _ if ok(s) => Ok(Name::Is(s.to_owned())),
        _ => Err(err),
    }
}

impl Scope {
    pub fn parse(s: &str) -> Result<Scope, ScopeError> {
        let (service, action, resource) = split(s)?;
        let service = name(service, service_ok, ScopeError::Service)?;
        let action = name(action, action_ok, ScopeError::Action)?;
        let resource = match resource {
            "*" => Resource::Any,
            _ if resource.len() > RESOURCE_MAX => return Err(ScopeError::Resource),
            _ => match resource.strip_suffix('*') {
                Some(p) if p.ends_with('/') && resource_ok(p) => Resource::Under(p.to_owned()),
                Some(_) => return Err(ScopeError::Resource),
                None if resource_ok(resource) => Resource::Is(resource.to_owned()),
                None => return Err(ScopeError::Resource),
            },
        };
        Ok(Scope {
            service,
            action,
            resource,
        })
    }

    /// Whether this scope allows `a`.
    pub fn covers(&self, a: &Action) -> bool {
        let name = |n: &Name, v: &str| matches!(n, Name::Any) || matches!(n, Name::Is(x) if x == v);
        name(&self.service, &a.service)
            && name(&self.action, &a.action)
            && match &self.resource {
                Resource::Any => true,
                Resource::Is(x) => *x == a.resource,
                Resource::Under(p) => {
                    a.resource.len() > p.len() && a.resource.starts_with(p.as_str())
                }
            }
    }

    /// Whether every action `child` covers, this scope covers too: what a
    /// narrower grant must show of each of its scopes.
    pub fn contains(&self, child: &Scope) -> bool {
        let name = |p: &Name, c: &Name| matches!(p, Name::Any) || p == c;
        name(&self.service, &child.service)
            && name(&self.action, &child.action)
            && match (&self.resource, &child.resource) {
                (Resource::Any, _) => true,
                (Resource::Is(p), Resource::Is(c)) => p == c,
                (Resource::Under(p), Resource::Is(c)) => {
                    c.len() > p.len() && c.starts_with(p.as_str())
                }
                (Resource::Under(p), Resource::Under(q)) => q.starts_with(p.as_str()),
                _ => false,
            }
    }
}

impl Action {
    pub fn parse(s: &str) -> Result<Action, ScopeError> {
        let (service, action, resource) = split(s)?;
        if !service_ok(service) {
            return Err(ScopeError::Service);
        }
        if !action_ok(action) {
            return Err(ScopeError::Action);
        }
        if !resource_ok(resource) {
            return Err(ScopeError::Resource);
        }
        Ok(Action {
            service: service.to_owned(),
            action: action.to_owned(),
            resource: resource.to_owned(),
        })
    }
}
