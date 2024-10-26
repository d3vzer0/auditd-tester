import argparse
from enum import Enum


class Permission(Enum):
    READ = "r"
    WRITE = "w"
    EXECUTE = "x"
    ATTRIBUTE = "a"


class ArgumentException(Exception):
    pass


class ArgumentParser(argparse.ArgumentParser):
    """Override for ArgumentParser
    to catch parsing errors

    Args:
        argparse (_type_): argparse
    """

    def error(self, message):
        raise ArgumentException(message)


class AuditObject:
    """AuditObject containing convertion methods"""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class AuditRule(AuditObject):
    """Object containing auditd rule attributes

    Args:
        AuditObject (_type_): AuditObject parent class
            containing convertion methods
    """

    def __init__(
        self,
        systemcall: str = None,
        filter: str = None,
        tag: str = None,
        file: str = None,
        action: str = None,
        activity: str = None,
        rule_type: str = None,
        error: bool = None,
    ):

        self.systemcall = systemcall
        self.filter = filter
        self.tag = tag
        self.file = file
        self.action = action
        self.activity = activity
        self.rule_type = rule_type
        self.error = error
        # super().__init__(self)

    @classmethod
    def from_string(cls, rule: str) -> "AuditRule":
        """Initialises AuditdRule by parsing an auditd rule
        string using ArgParse

        Args:
            rule (str): Auditd rule as string

        Returns:
            AuditRule: Parsed rule
        """
        parser = ArgumentParser()
        parser.add_argument(
            "-a",
            help="Action/Filter, ex: always,exit. Filter options: task, exit, user, and exclude",
        )
        parser.add_argument("-S", help="Name of the system call")
        parser.add_argument("-F", help="Key=Value pair or filters")
        parser.add_argument("-k", help="Label/tag added when a rule matches")
        parser.add_argument("-w", help="Path to file/directory for file system rules")
        parser.add_argument(
            "-p",
            help="Action performed on file/directory for file system rules (rwxa)",
        )

        try:
            args = parser.parse_args(rule.split())
            rule_type = "file" if args.w else "syscall"
            return cls(
                systemcall=args.S,
                action=args.a,
                filter=args.F,
                tag=args.k,
                file=args.w,
                activity=args.p,
                rule_type=rule_type,
            )

        except ArgumentException as parse_err:
            return cls(error=f"{parse_err}: {rule}")


class AuditRules:
    """Class containing parsed auditd rules and errors
    when loaded
    """

    def __init__(self, rules: list[AuditRule], errors=list[str]):
        self.rules = rules
        self.errors = errors

    @staticmethod
    def _filter_rules(rules: str) -> list[str]:
        """Returns a list of valid rules, ie. lines which are not comments
            or empty

        Args:
            rules (str): Auditd rule as string

        Returns:
            list[str]: Auditd rule as string
        """
        all_rules = []
        for rule in rules:
            rule = rule.strip()
            if not (rule.startswith("#") or rule == ""):
                all_rules.append(rule)
        return all_rules

    @classmethod
    def from_file(cls, path: str) -> "AuditRules":
        """Reads an auditd rule file and loads each entry
        as an AuditdRule object

        Args:
            path (str): Path to auditd rule file

        Returns:
            AuditRules: List of AuditdRule objects and load errors
        """
        all_rules = []
        parse_errors = []

        with open(path, "r") as auditd_file:
            valid_rules = AuditRules._filter_rules(auditd_file)

        for rule in valid_rules:
            rule_object = AuditRule.from_string(rule)
            if not rule_object.error:
                all_rules.append(rule_object)
            else:
                parse_errors.append(rule_object.error)

        return cls(rules=all_rules, errors=parse_errors)
