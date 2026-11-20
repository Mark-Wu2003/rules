"""Convert OpenAI's public ChatGPT Voice JSON to a Stash/Mihomo text IP rule set."""
import argparse
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener


SOURCE = 'https://openai.com/chatgpt-voice.json'
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / 'chatgpt-voice-ip.txt'
LIMIT = 524288


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Voice source redirected; review the official URL')


def fetch():
    request = Request(SOURCE, headers={'Accept': 'application/json', 'User-Agent': 'voice-rule-update/1'})
    with build_opener(NoRedirect()).open(request, timeout=25) as response:
        return response.read(LIMIT + 1)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Missing creationTime')
    date = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if date.utcoffset() is None:
        raise ValueError('creationTime requires a time zone')
    return date.astimezone(timezone.utc)


def parse_feed(raw):
    if len(raw) > LIMIT:
        raise ValueError('Oversized Voice feed')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError('Expected a JSON object')
    date, rows = timestamp(obj.get('creationTime')), obj.get('prefixes')
    if date > datetime.now(timezone.utc) + timedelta(hours=24):
        raise ValueError('Unexpected future feed timestamp')
    if not isinstance(rows, list) or not 32 <= len(rows) <= 8192:
        raise ValueError('Unexpected Voice feed size; keeping the previous list')
    result = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) not in ({'ipv4Prefix'}, {'ipv6Prefix'}):
            raise ValueError('Unknown Voice prefix schema')
        key, value = next(iter(row.items()))
        if not isinstance(value, str) or '/' not in value:
            raise ValueError('Expected a CIDR string')
        net = ipaddress.ip_network(value, strict=True)
        if (key != f'ipv{net.version}Prefix' or not net.is_global or net.is_multicast
                or net.prefixlen != net.max_prefixlen):
            raise ValueError(f'Not a public unicast host route: {net}; review upstream change')
        if net in result:
            raise ValueError(f'Duplicate prefix: {net}')
        result.add(net)
    return date, result


def update(raw, outputs):
    date, nets = parse_feed(raw)
    header = f'# Source: {SOURCE}\n# creationTime: '
    lines = [str(n) for n in sorted(nets, key=lambda n: (n.version, int(n.network_address)))]
    text = header + date.isoformat() + '\n' + '\n'.join(lines) + '\n'
    pending = []
    for path in outputs:
        if path.exists():
            old = path.read_text(encoding='ascii')
            if old == text:
                continue
            if not old.startswith(header):
                raise ValueError(f'Refusing to overwrite an unrecognized file: {path}')
            stamp, *previous = old[len(header):].splitlines()
            prior = timestamp(stamp)
            if date < prior or (date == prior and set(previous) != set(lines)):
                raise ValueError('Stale or inconsistent feed; retaining last known good data')
            if len(set(previous) - set(lines)) > len(previous) // 2:
                raise ValueError('More than half the previous destinations disappeared; review first')
        pending.append(path)
    for path in pending:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix='.voice-', dir=path.parent)
        tmp = Path(name)
        try:
            with os.fdopen(fd, 'w', encoding='ascii') as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
                os.fchmod(f.fileno(), 0o644)  # Public data, also read by the system daemon.
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    return len(lines), len(pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, help='Convert an already downloaded official JSON snapshot')
    parser.add_argument('outputs', type=Path, nargs='*', default=[DEFAULT_OUTPUT])
    args = parser.parse_args()
    if args.input:
        with args.input.open('rb') as f:
            raw = f.read(LIMIT + 1)
    else:
        raw = fetch()
    count, changed = update(raw, args.outputs or [DEFAULT_OUTPUT])
    print(f'{count} validated host routes; {changed} file(s) updated')


if __name__ == '__main__':
    main()
