from converter.auditd import AuditRules

if __name__ == "__main__":
    # TODO: Test, will be replaced by arg parser later
    rules = AuditRules.from_file("auditd.rules")
    for rule in rules.rules:
        if rule.rule_type == "file":
            print(rule.file, rule.activity)
