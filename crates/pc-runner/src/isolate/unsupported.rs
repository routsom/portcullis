//! Fail-closed backend for platforms without an isolation implementation.

use crate::Runner;
use crate::error::{Result, RunnerError};
use crate::spec::{RunOutcome, SandboxSpec};

/// A runner that refuses to execute because no sandbox is available. It still
/// validates the spec so misconfiguration surfaces the same way on every
/// platform.
#[derive(Debug, Default)]
pub struct UnsupportedRunner;

impl Runner for UnsupportedRunner {
    fn run(&self, spec: &SandboxSpec) -> Result<RunOutcome> {
        spec.validate()?;
        Err(RunnerError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_run_but_validates_first() {
        let r = UnsupportedRunner;
        // A well-formed spec is refused with Unsupported, never silently run.
        let spec = SandboxSpec::command("/bin/true", Vec::<String>::new());
        assert!(matches!(r.run(&spec), Err(RunnerError::Unsupported)));

        // An invalid spec is rejected as invalid, even here.
        let mut bad = spec;
        bad.argv.clear();
        assert!(matches!(r.run(&bad), Err(RunnerError::InvalidSpec(_))));
    }
}
