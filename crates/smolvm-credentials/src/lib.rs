//! Credential substitution for Smol machines.
//!
//! A machine declares *bindings* — names of credentials a workload may use,
//! each restricted to explicit destination hosts. The guest only ever receives
//! an opaque placeholder in the requested environment variable. The machine's
//! network backend redirects HTTPS flows to the [`intercept::Interceptor`],
//! which terminates TLS with a per-machine CA, swaps the placeholder for the
//! real value obtained from a [`resolver::CredentialResolver`], and forwards
//! the request upstream over an independently verified TLS connection. Flows
//! to hosts no binding covers are spliced through untouched.
//!
//! Credential *values* never enter the policy or the machine record: the
//! resolver is consulted per request, so rotation and revocation apply without
//! restarting the machine.

pub mod ca;
pub mod intercept;
pub mod policy;
pub mod resolver;
pub mod sni;

pub use ca::MachineCa;
pub use intercept::{Interceptor, InterceptorConfig};
pub use policy::{
    generate_placeholders, CredentialBinding, CredentialPolicy, InjectionLocation, PolicyError,
};
pub use resolver::{CredentialRequest, CredentialResolver, ResolveError, StaticResolver};
pub use smolvm_protocol::InterceptEndpoint;
