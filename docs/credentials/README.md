# Credentials a workload can use and never read

[Credential substitution](../credential-substitution.md) is the reference: bindings, where the
value comes from, what the guest sees, what happens to each request, the limits, and the external
interceptor. `SKILL.md` is the agent procedure, with scripts that prove on your own host that the
value stays out of the machine. This page records what the procedure measured beside the
reference.

## When a value from the environment is read

[Credential substitution](../credential-substitution.md#where-the-value-comes-from) says an
environment value is read at `machine start` and `machine exec` time. Observed on v1.18.2:
unsetting the variable for a later `machine exec` did not stop substitution, and starting the
machine with it unset gave `502 smolvm credentials: credential unavailable`. So rotate a value from
the environment by restarting the machine, and use a file reference for one that has to rotate
under a running machine.

## The bound host has to present a publicly trusted certificate

The interceptor checks the bound host's certificate against public roots and takes no root of
your own. Measured on v1.22.2 against a local HTTPS server with a self-signed certificate for the
bound name: the containment checks all passed, and the request carrying the placeholder came back
`502 smolvm credentials: upstream request failed`, with nothing reaching the server. A test endpoint
for this feature needs a certificate a public CA issued.
