# AuditD Test Generator

Convert AuditD rules into executable (Ansible) test cases to validate your system's auditd configuration.

## Overview

Auditd-tester is a tool that automatically transforms AuditD rules into runnable test cases for Ansible. This helps validating their audit configurations by:

- Verifying that AuditD rules are properly configured
- Testing if system events are being captured as expected

## Features

- Parses AuditD rules and generates corresponding test cases in the form of Ansible playbooks
- Creates test scenarios that trigger the audit events
- Validates that the expected audit logs are generated
- Supports common AuditD rule types including:
  - System calls
  - File system watches

## Installation

```bash
TODO
```

## Usage

1. Basic usage with a single rule file:
```bash
auditd-tester --rules /etc/audit/rules.d/audit.rules
```

## Example

Input AuditD rule (in a file):
```
-a always,exit -F arch=b64 -F path=/usr/bin/falcon-agent -p x -F key=falcon_agent
```

Generated test case:
```yaml
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
