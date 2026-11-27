"""Synthetic matcher/parser regressions. No network or account activity."""
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import verify_rules as v


class RulesTests(unittest.TestCase):
    def test_http_provider_example(self):
        config = yaml.load((v.ROOT / 'examples/ai-providers.yaml').read_text(), Loader=v.UniqueLoader)
        providers = config['rule-providers']
        expected = {'verification': ('verification.yaml', 'classical'), 'claude': ('claude.yaml', 'classical'),
                    'chatgpt': ('gpt.yaml', 'classical'), 'gemini': ('gemini.yaml', 'domain'),
                    'chatgpt_voice_ip': ('chatgpt-voice-ip.txt', 'ipcidr')}
        self.assertEqual(set(providers), set(expected))
        for name, (file, behavior) in expected.items():
            with self.subTest(provider=name):
                provider = providers[name]
                self.assertTrue((v.ROOT / file).is_file())
                self.assertEqual(provider['url'], 'https://raw.githubusercontent.com/Mark-Wu2003/rules/main/' + file)
                self.assertEqual((provider['type'], provider['behavior']), ('http', behavior))
                self.assertEqual(provider['format'], 'text' if behavior == 'ipcidr' else 'yaml')
                self.assertGreater(provider['interval'], 0)
                cache = PurePosixPath(provider['path'])
                self.assertFalse(cache.is_absolute())
                self.assertNotIn('..', cache.parts)
                self.assertEqual(cache.name, file)
        matches = [f'RULE-SET,{name}' for name in expected if name != 'chatgpt_voice_ip']
        matches.extend(f'AND,((NETWORK,{net}),(DST-PORT,{port}),(RULE-SET,chatgpt_voice_ip,no-resolve))'
                       for net, port in [('udp', 3478), ('tcp', 443)])
        self.assertEqual(config['rules'], [f'{match},{policy}' for match in matches
                                           for policy in ('AI_EGRESS', 'REJECT')])

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

    def test_second_anthropic_inbound_range(self):
        rules = v.load(Path(__file__).resolve().parents[1] / 'claude.yaml')
        for ip in ('153.61.224.0', '153.61.227.255'):
            self.assertTrue(v.covers(ip, rules))
        for ip in ('153.61.223.255', '153.61.228.0', '153.61.208.1'):
            self.assertFalse(v.covers(ip, rules))
        self.assertFalse(v.covers_network('153.61.208.0/20', rules))

    def test_process_is_not_domain_evidence(self):
        self.assertFalse(v.covers('api.anthropic.com', [('PROCESS-NAME', 'Claude')]))

    def test_gemini_provider_is_exact(self):
        rules = v.load(Path(__file__).resolve().parents[1] / 'gemini.yaml')
        self.assertTrue(v.covers('https://dl.google.com/release2/example/Gemini.dmg', rules))
        for host in ('dl.google.com.evil.example', 'sub.dl.google.com', 'mail.google.com', 'google.com',
                     'not-aicode.googleapis.com', 'sub.daily-cloudcode-pa.googleapis.com',
                     'antigravity-cli-auto-updater-974169037036.us-central1.run.app.evil.example',
                     'unrelated.us-central1.run.app'):
            with self.subTest(host=host):
                self.assertFalse(v.covers(host, rules))

    def test_invalid_and_overbroad_rules(self):
        for rule in ['DOMAIN-KEYWORD,claude', 'DOMAIN-SUFFIX,cloudflare.com', 'IP-ASN,13335',
                     'DOMAIN,cloudflare-ech.com', 'DOMAIN,example.com,AI', 'IP-CIDR,2607:6bc0::/48,no-resolve',
                     'DOMAIN-SUFFIX,api.aws', 'DOMAIN-SUFFIX,datadoghq.com',
                     'DOMAIN-SUFFIX,amazonaws.com', 'DOMAIN-SUFFIX,apple.com',
                     'DOMAIN-SUFFIX,cdn-apple.com', 'DOMAIN-SUFFIX,stripe.com',
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

    def test_live_endpoint_table_excludes_prose_destinations(self):
        table = ('<table><tr><th>URL</th><th>Required for</th></tr>'
                 '<tr><td><code>*-review.googlesource.com</code></td>'
                 '<td>Gerrit lookup for a googlesource.com checkout</td></tr>'
                 '<tr><td><code>api.anthropic.com</code></td><td>API</td></tr></table>')
        text = '<h2>Network access</h2>' + table + '<p>Other docs: example.com</p>'
        self.assertEqual(v.extract(v.section(text, 'Network access', 'URL')),
                         {'*-review.googlesource.com', 'api.anthropic.com'})
        for value in ('<h2>Network access</h2><p>api.anthropic.com</p>', text + table):
            with self.subTest(value=value), self.assertRaises(v.AuditError):
                v.section(value, 'Network access', 'URL')

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
