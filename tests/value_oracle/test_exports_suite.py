import io
import json
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timezone

import core
from suites import exports

FIXTURES = {
    'export_small': '11', 'export_composite': '12', 'export_objects': '13',
    'export_object_acl': '14', 'export_object_distribution': '15',
    'export_proposals': '16', 'export_proposal_delete': '17',
    'export_largest': '18',
}
DEBUG_BLOCK = (
    '<pre class="cake-error"><a href="javascript:void(0);" onclick="x(\'cake'
    'Err6abf5e\')"><b>Warning</b> (2)</a>: Undefined array key '
    '&quot;value&quot; [<b>APP/Lib/Export/HostsExport.php</b>, line <b>47</b>]'
    '<div id="cakeErr6a'
    'bf5e-trace" class="cake-stack-trace" style="display: none;"><pre id="cak'
    'eErr6abf5e-code" class="cake-code-dump"><pre><code>x</code></pre></pre>'
    '<pre class="stack-trace">HostsExport::handler() - APP/Lib/Export/HostsE'
    'xport.php, line 31</pre></div></pre>')


def build(fixtures):
    with tempfile.NamedTemporaryFile('w', suffix='.json') as f:
        json.dump(fixtures, f)
        f.flush()
        config = core.Config('http://x', {}, '/tmp', fixtures=f.name)
        return exports.cases(config)


class CasesTest(unittest.TestCase):
    def test_names_unique(self):
        names = [c.name for c in build(FIXTURES)]
        self.assertEqual(len(names), len(set(names)))

    def test_every_case_ignores_row_order(self):
        self.assertTrue(all(c.unordered for c in build(FIXTURES)))

    def test_every_format_per_scope(self):
        by_name = {c.name for c in build(FIXTURES)}
        for fmt in exports.EVENT_FORMATS:
            self.assertIn('event.small.%s.admin' % fmt, by_name)
        for fmt in exports.ATTRIBUTE_FORMATS:
            self.assertIn('attr.small.%s.admin' % fmt, by_name)
        self.assertNotIn('attr.small.attack.admin', by_name)
        self.assertFalse(any('opendata' in n for n in by_name))

    def test_lesser_runs_only_json_and_csv(self):
        lesser = [c for c in build(FIXTURES) if c.user == 'lesser']
        self.assertEqual(
            {'json', 'csv'}, {c.body['returnFormat'] for c in lesser})
        self.assertEqual(len(exports.SAMPLE) * 2 * 2, len(lesser))

    def test_hanging_cases_are_skipped(self):
        names = {c.name for c in build(FIXTURES)}
        self.assertNotIn('attr.objects.stix.admin', names)
        self.assertIn('event.objects.stix.admin', names)
        self.assertIn('attr.objects.stix2.admin', names)

    def test_stix_asks_for_xml(self):
        by_name = {c.name: c for c in build(FIXTURES)}
        self.assertEqual('application/xml',
                         by_name['event.small.stix.admin'].accept)
        self.assertEqual({'eventid': '11', 'returnFormat': 'stix'},
                         by_name['event.small.stix.admin'].body)

    def test_missing_sample_event_is_skipped(self):
        names = {c.name for c in build(dict(FIXTURES, export_largest=None))}
        self.assertFalse(any('.largest.' in n for n in names))
        self.assertIn('event.small.json.admin', names)


class NormaliseTest(unittest.TestCase):
    def setUp(self):
        self.now = time.time()

    def window(self):
        return self.now - 10, self.now + 10

    def stamp(self, offset=0, fmt='%Y-%m-%dT%H:%M:%S', utc=True):
        moment = datetime.fromtimestamp(
            self.now + offset, timezone.utc if utc else None)
        return moment.strftime(fmt)

    def test_php_debug_block_collapses(self):
        text = exports.collapse_php_debug(DEBUG_BLOCK + DEBUG_BLOCK + 'rest')
        self.assertEqual(
            '[php Warning: Undefined array key &quot;value&quot; in '
            'APP/Lib/Export/HostsExport.php]\n' * 2 + 'rest', text)

    def test_unterminated_debug_block_is_kept(self):
        out = exports.collapse_php_debug(
            '<pre class="cake-error">broken ' + DEBUG_BLOCK + 'rest')
        self.assertTrue(out.startswith('<pre class="cake-error">broken '))
        self.assertTrue(out.endswith('HostsExport.php]\nrest'))

    def test_generated_timestamps_are_masked(self):
        text = ' '.join([
            self.stamp() + 'Z',
            self.stamp() + '.123456+00:00',
            self.stamp(fmt='%Y-%m-%d %H:%M:%S') + ' +0000',
            self.stamp(utc=False) + '.551011',
            self.stamp(),
        ])
        masked = exports.mask_generated(text, *self.window())
        self.assertEqual(' '.join(['<generated>'] * 5), masked)

    def test_data_timestamps_are_kept(self):
        text = '2018-03-23T13:11:05+00:00 %s 2026-13-45T00:00:00' % (
            self.stamp(-3600) + 'Z')
        self.assertEqual(text, exports.mask_generated(text, *self.window()))

    def test_day_granular_stamps(self):
        rpz = exports.normalise(
            'rpz', '@ SOA localhost. root.localhost (2026100200 2h 30m)',
            *self.window())
        self.assertEqual('@ SOA localhost. root.localhost (<serial> 2h 30m)',
                         rpz)
        suricata = exports.normalise(
            'suricata', 'created_at 2018_03_23,updated_at 2026_10_02;',
            *self.window())
        self.assertEqual('created_at 2018_03_23,updated_at <today>;',
                         suricata)

    def test_stix_package_and_bundle_ids(self):
        root = 'ORGNAME:STIXPackage-8b040d6d-4255-4b13-93c8-7b1859ed1d1b'
        inner = 'ORGNAME:STIXPackage-5ab4fbe3-3c98-4cf9-9a80-04b3ac1b880d'
        out = exports.normalise('stix', root + ' ' + inner,
                                *self.window())
        self.assertEqual('ORGNAME:STIXPackage-<random> ' + inner, out)
        bundle = '{"id": "bundle--ff5b9700-e5f5-4944-97b6-984f1e3e10a0"}'
        self.assertEqual('{"id": "bundle--<random>"}',
                         exports.normalise('stix2', bundle, *self.window()))

    def test_yara_multi_attribute_rule_name(self):
        text = 'rule MISP_MULTI_ATTRIBUTES_1b9c0a4e8f2d4c6a9e3b7d5f1a2c4e6b {'
        self.assertEqual(
            'rule MISP_MULTI_ATTRIBUTES_<random> {',
            exports.normalise('yara', text, *self.window()))

    def test_temp_file_names(self):
        text = 'yaraexport.py --input /var/www/MISP/app/tmp/MISPg0mxXe failed'
        self.assertEqual(
            'yaraexport.py --input /var/www/MISP/app/tmp/MISP<tmp> failed',
            exports.normalise('yara', text, *self.window()))
        escaped = '{"message": "--input \\/app\\/tmp\\/MISPROsB0l --raw"}'
        self.assertEqual(
            '{"message": "--input \\/app\\/tmp\\/MISP<tmp> --raw"}',
            exports.normalise('yara-json', escaped, *self.window()))

    def test_xlsx_members(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('xl/worksheets/sheet1.xml', '<row>1.2.3.4</row>')
            archive.writestr('[Content_Types].xml', '<Types/>')
        response = core.Response(
            200, {'content-type': 'application/vnd.x', 'X-Result-Count': '3'},
            buffer.getvalue(), *self.window())
        value = exports.export_body('xlsx')(response)
        self.assertEqual(['[Content_Types].xml', 'xl/worksheets/sheet1.xml'],
                         list(value['body']))
        self.assertEqual('application/vnd.x', value['content_type'])
        self.assertEqual('3', value['result_count'])

    def test_xlsx_error_body_is_text(self):
        response = core.Response(500, {}, b'{"name": "error"}',
                                 *self.window())
        value = exports.export_body('xlsx')(response)
        self.assertEqual('{"name": "error"}', value['body'])


if __name__ == '__main__':
    unittest.main()
