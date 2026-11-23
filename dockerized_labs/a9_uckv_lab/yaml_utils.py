import yaml


def parse_yaml(stream):
    """Parse a YAML document using the safe loader.

    yaml.safe_load only builds standard scalar/sequence/mapping types, so a
    malicious document cannot instantiate arbitrary Python objects (CWE-502).
    """
    return yaml.safe_load(stream)
