#!/usr/bin/env python3
"""Offline routing-contract checks; --live also inspects five official doc sections.

Does not connect through a proxy, perform DNS, or test account access. Live checks
never edit production rules. Fetch/parser failures are failures, not green passes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = ('claude.yaml', 'gpt.yaml', 'verification.yaml')
BRANDS = {'claude', 'anthropic', 'openai', 'chatgpt'}
BROAD = {'cloudflare.com', 'cloudflare.net', 'akamaized.net', 'fastly.net',
         'googleapis.com', 'googleusercontent.com', 'github.com'}
GERRIT = r'^.+-review\.googlesource\.com$'


class AuditError(ValueError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    loader.flatten_mapping(node)
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise AuditError(f'Duplicate or invalid YAML key: {key!r}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def host(target: str) -> str:
    value = target.strip()
    try:
        return str(ipaddress.ip_address(value.strip('[]')))
    except ValueError:
        parsed = urlsplit(value if '://' in value else '//' + value)
        if not parsed.hostname:
            raise AuditError(f'Missing hostname: {target!r}')
        return parsed.hostname.rstrip('.').encode('idna').decode('ascii').lower()


def parse_rule(text: str) -> tuple[str, str]:
    parts = [part.strip() for part in text.split(',')]
    if len(parts) < 2 or not parts[1]:
        raise AuditError(f'Malformed rule: {text}')
    kind, value, *options = parts
    allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX',
               'IP-CIDR', 'IP-CIDR6', 'PROCESS-NAME'}
    if kind not in allowed:
        raise AuditError(f'Unsupported selector: {text}')
    if kind in {'IP-CIDR', 'IP-CIDR6'}:
        net = ipaddress.ip_network(value, strict=True)
        if net.version != (4 if kind == 'IP-CIDR' else 6) or net.prefixlen == 0:
            raise AuditError(f'Invalid IP rule: {text}')
        if options != ['no-resolve']:
            raise AuditError(f'Expected no-resolve and no policy name: {text}')
    elif options:
        raise AuditError(f'Unexpected options/policy in classical provider: {text}')
    if kind in {'DOMAIN', 'DOMAIN-SUFFIX'}:
        label = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
        if not re.fullmatch(rf'{label}(?:\.{label})+', value):
            raise AuditError(f'Expected literal lower-case domain: {text}')
    if kind == 'DOMAIN-REGEX':
        re.compile(value)
        if not (value.startswith('^') and value.endswith('$')):
            raise AuditError(f'Unanchored domain regex: {text}')
    if kind == 'DOMAIN-KEYWORD' and value in BRANDS:
        raise AuditError(f'Unbounded AI brand keyword: {text}')
    if kind == 'DOMAIN-SUFFIX' and value in BROAD:
        raise AuditError(f'Provider-wide shared-infrastructure catch-all: {text}')
    if value == 'cloudflare-ech.com':
        raise AuditError('ECH outer SNI does not identify an AI tenant')
    return kind, value


def load(path: Path) -> list[tuple[str, str]]:
    data = yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueLoader)
    if not isinstance(data, dict) or set(data) != {'payload'}:
        raise AuditError(f'{path}: expected only a payload mapping')
    raw = data['payload']
    if not isinstance(raw, list) or not raw or not all(isinstance(x, str) for x in raw):
        raise AuditError(f'{path}: expected a nonempty list of rule strings')
    if len(raw) != len(set(raw)):
        raise AuditError(f'{path}: duplicate active rule')
    return [parse_rule(rule) for rule in raw]


def match(rule: tuple[str, str], hostname: str) -> bool:
    kind, value = rule
    if kind == 'DOMAIN':
        return hostname == value
    if kind == 'DOMAIN-SUFFIX':
        return hostname == value or hostname.endswith('.' + value)
    if kind == 'DOMAIN-KEYWORD':
        return value in hostname
    if kind == 'DOMAIN-REGEX':
        return re.search(value, hostname) is not None
    if kind in {'IP-CIDR', 'IP-CIDR6'}:
        try:
            return ipaddress.ip_address(hostname) in ipaddress.ip_network(value)
        except ValueError:
            return False
    return False  # Process selectors cannot prove hostname coverage, especially on iOS.


def covers(target: str, rules: list[tuple[str, str]]) -> bool:
    if '*' not in target:
        return any(match(rule, host(target)) for rule in rules)
    # Require a general suffix, not a handful of guessed positive subdomains.
    labels = target.lower().split('.')
    suffix = '.'.join(labels[max(i for i, label in enumerate(labels) if '*' in label) + 1:])
    if suffix and any(kind == 'DOMAIN-SUFFIX' and match((kind, value), suffix)
                      for kind, value in rules):
        return True
    return target == '*-review.googlesource.com' and ('DOMAIN-REGEX', GERRIT) in rules


def covers_network(target: str, rules: list[tuple[str, str]]) -> bool:
    required = ipaddress.ip_network(target, strict=True)
    for kind, value in rules:
        if kind in {'IP-CIDR', 'IP-CIDR6'}:
            network = ipaddress.ip_network(value)
            if required.version == network.version and required.subnet_of(network):
                return True
    return False


def audit(root: Path, corpus: dict) -> dict:
    rules = {name: load(root / name) for name in FILES}
    failures, groups = [], []
    declarations = passed = wildcards = flows = negatives = 0
    for group in corpus['groups']:
        if group['source'] not in corpus['sources']:
            raise AuditError(f'Missing source: {group["name"]}')
        checked = good = 0
        for name in group['providers']:
            for field, checker in [('domains', covers), ('networks', covers_network)]:
                for target in group.get(field, []):
                    checked += 1
                    wildcards += '*' in target
                    ok = checker(target, rules[name])
                    good += ok
                    if not ok:
                        failures.append(f'{name}: uncovered {target}')
        declarations += checked
        passed += good
        groups.append({'name': group['name'], 'passed': good, 'checked': checked})
    for flow in corpus['constructed_flows']:
        combined = [rule for name in flow['providers'] for rule in rules[name]]
        for target in flow['targets']:
            flows += 1
            if not covers(target, combined):
                failures.append(f'Constructed URL not covered: {target}')
    for name in FILES:
        for target in corpus['negative_targets']:
            negatives += 1
            if covers(target, rules[name]):
                failures.append(f'{name}: unwanted match {target}')
    return {'reviewed_at': corpus['reviewed_at'], 'rule_counts': {k: len(v) for k, v in rules.items()},
            'declaration_checks': declarations, 'declaration_passed': passed,
            'wildcard_checks': wildcards, 'constructed_url_checks': flows,
            'negative_checks': negatives, 'groups': groups, 'failures': failures,
            'real_network_validated': False}


def normalized(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', text.lower()).strip()


def section(document: str, heading: str) -> str:
    candidates = []
    if re.search(r'<h[1-6]\b', document, re.I):
        from bs4 import BeautifulSoup, NavigableString, Tag
        soup = BeautifulSoup(document, 'html.parser')
        for element in soup.select('script, style, nav, header, footer'):
            element.decompose()
        headings = soup.find_all(re.compile(r'^h[1-6]$'))
        for tag in headings:
            if normalized(tag.get_text(' ', strip=True)) != normalized(heading):
                continue
            pieces = []
            for item in tag.next_elements:
                if isinstance(item, Tag) and re.fullmatch(r'h[1-6]', item.name or '') and int(item.name[1]) <= int(tag.name[1]):
                    break
                if isinstance(item, NavigableString):
                    pieces.append(str(item))
            candidates.append('\n'.join(pieces))
    else:
        lines = document.splitlines()
        for index, line in enumerate(lines):
            h = re.match(r'^(#{1,6})\s+(.+?)\s*#*\s*$', line)
            if not h or normalized(h[2]) != normalized(heading):
                continue
            pieces = []
            for following in lines[index + 1:]:
                nxt = re.match(r'^(#{1,6})\s+', following)
                if nxt and len(nxt[1]) <= len(h[1]):
                    break
                pieces.append(following)
            candidates.append('\n'.join(pieces))
    if len(candidates) != 1 or not candidates[0].strip():
        raise AuditError(f'Expected one nonempty section {heading!r}, found {len(candidates)}')
    return candidates[0]


def extract(text: str, kind: str = 'domains') -> set[str]:
    if kind == 'networks':
        values = re.findall(r'(?<![\w:./])([0-9a-fA-F:.]+/[0-9]{1,3})(?![\w./])', text)
        return {str(ipaddress.ip_network(value, strict=True)) for value in values}
    values = re.findall(r'(?<![\w.@-])(?:[a-z0-9*][a-z0-9*-]*\.)+[a-z]{2,63}(?![\w.-])', text.lower())
    extensions = {'json', 'yaml', 'yml', 'md', 'txt', 'js', 'ts', 'py', 'html'}
    return {value for value in values if value.rsplit('.', 1)[-1] not in extensions}


def live_audit(root: Path, corpus: dict) -> list[dict]:
    rules = {name: load(root / name) for name in FILES}
    results = []
    for source_id, source in corpus['sources'].items():
        spec = source.get('live')
        if not spec:
            continue
        result = {'source': source_id, 'url': source['url'], 'ok': False}
        try:
            if urlsplit(source['url']).scheme != 'https':
                raise AuditError('Official source must use HTTPS')
            request = Request(source['url'], headers={'User-Agent': 'rules-domain-audit/1.0', 'Accept': 'text/html,text/markdown;q=0.9'})
            with urlopen(request, timeout=20) as response:
                if urlsplit(response.url).scheme != 'https':
                    raise AuditError('Refusing insecure redirect')
                body = response.read(4_000_001)
            if len(body) > 4_000_000:
                raise AuditError('Document exceeds 4 MB limit')
            targets = extract(section(body.decode('utf-8'), spec['heading']), spec.get('kind', 'domains'))
            if len(targets) < spec['minimum']:
                raise AuditError(f'Only {len(targets)} targets parsed; expected at least {spec["minimum"]}. Review parser/source drift.')
            checker = covers_network if spec.get('kind') == 'networks' else covers
            missing = [f'{name}: {target}' for name in spec['providers'] for target in sorted(targets) if not checker(target, rules[name])]
            result.update(ok=not missing, parsed_targets=len(targets), uncovered=missing)
        except Exception as error:
            result['error'] = f'{type(error).__name__}: {error}'
        results.append(result)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        corpus = json.loads((args.root / 'tests/routing-corpus.json').read_text(encoding='utf-8'))
        result = audit(args.root, corpus)
        if args.live:
            result['upstream'] = live_audit(args.root, corpus)
        output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
        if args.report:
            args.report.write_text(output, encoding='utf-8')
        print(output, end='')
        return int(bool(result['failures']) or any(not entry['ok'] for entry in result.get('upstream', [])))
    except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
        print(f'AUDIT FAILED: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
