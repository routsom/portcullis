//! An invocation: the fully-identified "who is calling what, in what tenant,
//! with what argument shape" that a [`Decision`](crate::Decision) is made about.

use serde::{Deserialize, Serialize};

use crate::{CapabilityId, DelegationChain, TenantId, hash::ArgShapeHash};

/// Everything the gateway needs to authorize a call, with no wire-protocol
/// detail attached. Argument *values* are deliberately absent: only the
/// [`ArgShapeHash`] is carried, which is what the decision cache keys on
/// (CLAUDE.md §5 row #1) and keeps values out of cache keys and logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invocation {
    pub tenant: TenantId,
    pub chain: DelegationChain,
    pub capability: CapabilityId,
    pub arg_shape: ArgShapeHash,
}

impl Invocation {
    #[must_use]
    pub fn new(
        tenant: TenantId,
        chain: DelegationChain,
        capability: CapabilityId,
        arg_shape: ArgShapeHash,
    ) -> Self {
        Self {
            tenant,
            chain,
            capability,
            arg_shape,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Digest;
    use crate::{Principal, PrincipalId, PrincipalKind};

    #[test]
    fn carries_tenant_principal_and_capability_when_constructed() {
        let inv = Invocation::new(
            TenantId::new("acme").unwrap(),
            DelegationChain::root(Principal::new(PrincipalId::new("svc"), PrincipalKind::Pat)),
            CapabilityId::new("echo"),
            ArgShapeHash::new(Digest::of(b"{msg:string}")),
        );
        assert_eq!(inv.tenant.as_str(), "acme");
        assert_eq!(inv.capability.as_str(), "echo");
        assert_eq!(inv.chain.depth(), 1);
    }
}
