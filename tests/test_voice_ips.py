import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import update_voice_ips as voice


def feed(rows=None, date='2026-01-02T00:00:00Z'):
    if rows is None:
        rows = [{'ipv4Prefix': f'9.9.9.{i}/32'} for i in range(1, 34)]
    return json.dumps({'creationTime': date, 'prefixes': rows}).encode()


class VoiceFeedTests(unittest.TestCase):
    def test_roundtrip_order_and_idempotence(self):
        rows = json.loads(feed())['prefixes'] + [{'ipv6Prefix': '2606:4700:4700::1111/128'}]
        with tempfile.TemporaryDirectory() as tmp:
            a, b = (Path(tmp) / name for name in ('a/list.txt', 'b/list.txt'))
            self.assertEqual(voice.update(feed(rows[::-1]), [a, b]), (34, 2))
            self.assertEqual(a.read_bytes(), b.read_bytes())
            self.assertEqual(a.read_text().splitlines()[2:5], ['9.9.9.1/32', '9.9.9.2/32', '9.9.9.3/32'])
            self.assertEqual(voice.update(feed(rows), [a, b]), (34, 0))

    def test_failures_preserve_previous_file(self):
        rows = json.loads(feed())['prefixes']
        candidates = [b'<html>error</html>', b'x' * (voice.LIMIT + 1), feed([]),
                      feed(rows, '2025-12-31T00:00:00Z'), feed(rows, '2026-01-02'),
                      feed(rows, '2999-01-01T00:00:00Z'), feed(rows + [rows[0]]),
                      feed([{'ipv4Prefix': f'8.8.8.{i}/32'} for i in range(1, 34)], '2026-01-03T00:00:00Z')]
        for invalid in ('0.0.0.0/0', '10.0.0.1/32', '224.0.0.1/32', '1.1.1.0/24', '8.8.8.8'):
            candidates.append(feed(rows + [{'ipv4Prefix': invalid}]))
        candidates.extend([feed(rows + [{'ipv6Prefix': '1.1.1.1/32'}]),
                           feed(rows + [{'unexpected': '1.1.1.1/32'}])])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'voice.txt'
            voice.update(feed(), [path])
            original = path.read_bytes()
            for raw in candidates:
                with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                    voice.update(raw, [path])
                self.assertEqual(path.read_bytes(), original)

    def test_preflight_all_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = (Path(tmp) / name for name in ('a', 'b'))
            b.write_text('unrelated file')
            with self.assertRaises(ValueError):
                voice.update(feed(), [a, b])
            self.assertFalse(a.exists())
            self.assertEqual(b.read_text(), 'unrelated file')

    def test_small_upstream_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'voice.txt'
            voice.update(feed(), [path])
            rows = json.loads(feed())['prefixes']
            rows[0] = {'ipv4Prefix': '8.8.8.8/32'}
            with self.assertRaises(ValueError):
                voice.update(feed(rows), [path])
            self.assertEqual(voice.update(feed(rows, '2026-01-03T00:00:00Z'), [path]), (33, 1))
            self.assertIn('8.8.8.8/32', path.read_text().splitlines())
            self.assertNotIn('9.9.9.1/32', path.read_text().splitlines())
