"""Synthetic matcher/parser regressions. No network or account activity."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import verify_rules as v


class RulesTests(unittest.TestCase):
    def test_suffix_boundaries(self):
        rules = [v.parse_rule('DOMAIN-SUFFIX,claude.ai')]
        for name in ['claude.ai', 'api.claude.ai', 'a.b.claude.ai']:
            self.assertTrue(v.covers(name, rules))
        for name in ['notclaude.ai', 'claude.ai.evil.example']:
            self.assertFalse(v.covers(name, rules))

    def test_url_normalization(self):
        self.assertEqual(v.host('https://API.CLAUDE.AI.:443/path?q=1'), 'api.claude.ai')
        self.assertEqual(v.host('wss://bridge.claudeusercontent.com/'), 'bridge.claudeusercontent.com')
        self.assertEqual(v.host('2607:6bc0::1'), '2607:6bc0::1')
        self.assertEqual(v.host('https://[2607:6bc0::1]:443/'), '2607:6bc0::1')

    def test_query_does_not_identify_host(self):
        self.assertFalse(v.covers('https://evil.example/?next=https://claude.ai/', [('DOMAIN-SUFFIX', 'claude.ai')]))

    def test_wildcard_requires_general_coverage(self):
        self.assertFalse(v.covers('*.claude.app', [('DOMAIN', 'test.claude.app')]))
        self.assertTrue(v.covers('*.livepreview.claude.app', [('DOMAIN-SUFFIX', 'claude.app')]))
        self.assertTrue(v.covers('*-review.googlesource.com', [('DOMAIN-REGEX', v.GERRIT)]))

    def test_ip_bounds_and_no_dns(self):
        rules = [v.parse_rule('IP-CIDR,160.79.104.0/23,no-resolve'), v.parse_rule('IP-CIDR6,2607:6bc0::/48,no-resolve')]
        for name in ['160.79.104.0', '160.79.105.255', '2607:6bc0::1']:
            self.assertTrue(v.covers(name, rules))
        for name in ['160.79.103.255', '160.79.106.0', '2607:6bc0:1::1', 'api.anthropic.com']:
            self.assertFalse(v.covers(name, rules))
        self.assertTrue(v.covers_network('160.79.104.0/23', rules))
        self.assertFalse(v.covers_network('160.79.104.0/21', rules))

    def test_process_is_not_domain_evidence(self):
        self.assertFalse(v.covers('api.anthropic.com', [('PROCESS-NAME', 'Claude')]))

    def test_invalid_and_overbroad_rules(self):
        for rule in ['DOMAIN-KEYWORD,claude', 'DOMAIN-SUFFIX,cloudflare.com', 'IP-ASN,13335',
                     'DOMAIN,cloudflare-ech.com', 'DOMAIN,example.com,AI', 'IP-CIDR,2607:6bc0::/48,no-resolve',
                     'IP-CIDR,0.0.0.0/0,no-resolve', 'DOMAIN-SUFFIX,*.claude.ai', 'DOMAIN-REGEX,claude']:
            with self.subTest(rule=rule), self.assertRaises(v.AuditError):
                v.parse_rule(rule)

    def test_duplicate_yaml_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.yaml'
            path.write_text('payload: []\npayload: []\n')
            with self.assertRaises(v.AuditError):
                v.load(path)

    def test_html_bounded_section(self):
        text = '<nav><h2>Required</h2>outside.example</nav><h2>Required</h2><p>api.example.com *.content.example.app</p><script>hidden.example.com</script><h3>Optional</h3><p>cdn.example.net</p><h2>Next</h2>outside.example'
        self.assertEqual(v.extract(v.section(text, 'Required')), {'api.example.com', '*.content.example.app', 'cdn.example.net'})

    def test_markdown_and_new_tld(self):
        text = '## Required\napi.example.tech\n### Optional\n*-review.googlesource.com\n## Next\nnot.example'
        self.assertEqual(v.extract(v.section(text, 'Required')), {'api.example.tech', '*-review.googlesource.com'})

    def test_missing_or_ambiguous_section_fails(self):
        for text in ['<h2>Other</h2>api.example.com', '<h2>Required</h2>a.example<h2>Required</h2>b.example']:
            with self.assertRaises(v.AuditError):
                v.section(text, 'Required')

    def test_inbound_not_outbound(self):
        text = '## Inbound\n### IPv4\n160.79.104.0/23\n### IPv6\n2607:6bc0::/48\n## Outbound\n160.79.104.0/21'
        self.assertEqual(v.extract(v.section(text, 'Inbound'), 'networks'), {'160.79.104.0/23', '2607:6bc0::/48'})


if __name__ == '__main__':
    unittest.main()
