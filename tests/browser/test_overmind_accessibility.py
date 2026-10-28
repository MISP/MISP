#!/usr/bin/env python3
"""Shared Overmind template and keyboard regression checks in Chromium.

Requires PHP and Python Playwright. Run from any directory:
  python tests/browser/test_overmind_accessibility.py
Optional: --root /path/to/another/checkout --php /path/to/php
Set CHROMIUM_PATH to use an installed Chromium instead of Playwright's browser.
No MISP database, server, credentials or network requests are needed.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import unittest

from playwright.sync_api import expect, sync_playwright


class AccessibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = Path(__file__).with_name('overmind-accessibility-fixture.php')
        cls.fixtures = json.loads(subprocess.check_output(
            [ARGS.php, str(fixture), str(ARGS.root)], text=True
        ))
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(
            executable_path=os.environ.get('CHROMIUM_PATH') or None,
            headless=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.page = self.browser.new_page()
        self.errors = []
        self.page.on('pageerror', lambda error: self.errors.append(str(error)))

    def tearDown(self):
        self.page.close()
        self.assertEqual([], self.errors)

    def styles(self):
        for name in ['themes/overmind.min.css', 'mainOvermind.css']:
            # External CSS decodes a UTF-8 BOM before parsing. Do the same
            # when injecting the stylesheet as an inline test resource.
            self.page.add_style_tag(content=(
                ARGS.root / 'app/webroot/css' / name
            ).read_text(encoding='utf-8-sig'))

    def test_selection_names_and_focus(self):
        self.page.set_content('<table>' + self.fixtures['headers']
                              + '<tbody><tr><td>' + self.fixtures['checkbox']
                              + '</td><td>Example</td></tr></tbody></table>'
                              + self.fixtures['selector'])
        self.styles()
        name = 'Select item 42 <tag> & "quoted"'
        expect(self.page.get_by_role('checkbox', name=name)).to_have_count(2)
        expect(self.page.get_by_role('button', name=
               'Actions for item 42 <tag> & "quoted"')).to_have_count(1)
        select_all = self.page.get_by_role(
            'checkbox', name='Select all items on this page'
        )
        self.page.keyboard.press('Tab')
        expect(select_all).to_be_focused()
        outline = select_all.evaluate(
            '(el) => [getComputedStyle(el).outlineStyle, '
            'getComputedStyle(el).outlineWidth]'
        )
        self.assertEqual(['solid', '2px'], outline)
        self.assertEqual('', self.fixtures['proposal'])
        self.assertIn('<th scope="col"', self.fixtures['headers'])

    def test_pagination_first_middle_last(self):
        for number in [1, 6, 12]:
            with self.subTest(page=number):
                self.page.set_content(self.fixtures[f'page{number}'])
                current = self.page.locator('[aria-current="page"]')
                expect(current.get_by_text(f'Page {number}', exact=True)).to_have_count(1)
                self.assertIsNone(current.get_attribute('href'))
                for link in self.page.locator('a.page-link').all():
                    label = link.get_attribute('aria-label')
                    self.assertTrue(label)
                    if link.inner_text().isdigit():
                        self.assertEqual('Page ' + link.inner_text(), label)
                if number == 1:
                    expect(self.page.locator('.page-link[aria-disabled="true"]')).to_have_text(
                        'Previous page'
                    )
                if number == 12:
                    expect(self.page.locator('.page-link[aria-disabled="true"]')).to_have_text(
                        'Next page'
                    )
                expect(self.page.locator('i:not([aria-hidden="true"])')).to_have_count(0)

    def test_skip_link(self):
        self.page.set_content(self.fixtures['skip']
                              + '<nav><a href="#menu">Menu</a></nav>'
                              + '<main id="main-content" tabindex="-1">'
                              + '<button>Content action</button></main>')
        self.styles()
        skip = self.page.get_by_role('link', name='Skip to main content')
        self.page.keyboard.press('Tab')
        expect(skip).to_be_focused()
        self.assertGreaterEqual(skip.bounding_box()['y'], 0)
        self.page.keyboard.press('Enter')
        expect(self.page.get_by_role('main')).to_be_focused()
        self.page.keyboard.press('Tab')
        expect(self.page.get_by_role('button', name='Content action')).to_be_focused()
        for layout in ['default', 'dashboard']:
            source = (ARGS.root / 'app/View/Themed/Overmind/Layouts'
                      / f'{layout}.ctp').read_text()
            self.assertIn("$this->element('skip_link')", source)
            self.assertIn('id="main-content" tabindex="-1"', source)

    def modal_fixture(self):
        self.page.set_content('<button id="opener">Open dialog</button>'
                              + '<button id="other">Other opener</button>'
                              + self.fixtures['chrome'])
        self.styles()
        self.page.add_script_tag(path=str(
            ARGS.root / 'app/webroot/js/bootstrap.bundle.min.js'
        ))
        self.page.add_script_tag(path=str(
            ARGS.root / 'app/webroot/js/mispOvermind.js'
        ))
        self.page.evaluate('''() => {
            document.getElementById('opener').onclick = () => showConfirmModal({
                title: 'Delete <example>?', body: '<p>Review before deleting.</p>'
            });
            document.getElementById('other').onclick = () => showConfirmModal({});
        }''')

    def test_dialog_name_replacement_and_fallback(self):
        self.modal_fixture()
        self.page.get_by_role('button', name='Open dialog').click()
        dialog = self.page.get_by_role('dialog', name='Delete <example>?', exact=True)
        expect(dialog).to_be_visible()
        self.page.evaluate('''() => {
            document.getElementById('mainModalBody').innerHTML =
                '<h4 id="existing-title">Replacement title</h4>' +
                '<button data-bs-dismiss="modal">Close</button>';
        }''')
        expect(self.page.get_by_role('dialog', name='Replacement title')).to_be_visible()
        expect(dialog).to_have_count(0)
        expect(self.page.locator('#mainModal')).to_have_attribute(
            'aria-labelledby', 'existing-title'
        )
        self.page.get_by_role('button', name='Close', exact=True).click()
        expect(self.page.locator('#mainModal')).not_to_be_visible()
        self.page.get_by_role('button', name='Other opener').click()
        expect(self.page.get_by_role('dialog', name='Dialog', exact=True)).to_be_visible()
        expect(self.page.locator('#mainModal')).not_to_have_attribute('aria-labelledby')

    def test_dialog_escape_restores_keyboard_focus(self):
        self.modal_fixture()
        self.page.keyboard.press('Tab')
        opener = self.page.get_by_role('button', name='Open dialog')
        expect(opener).to_be_focused()
        self.page.keyboard.press('Enter')
        expect(self.page.locator('#mainModal')).to_be_focused()
        self.page.keyboard.press('Tab')
        expect(self.page.get_by_role('button', name='Cancel')).to_be_focused()
        self.page.keyboard.press('Escape')
        expect(self.page.locator('#mainModal')).not_to_be_visible()
        expect(opener).to_be_focused()

    def test_legacy_containers_unchanged(self):
        self.page.set_content(self.fixtures['legacyChrome'])
        expect(self.page.locator('#mainModal')).to_have_count(0)
        expect(self.page.locator('#popover_form_large')).to_have_count(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument('--php', default='php')
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
