<?php
/**
 * Overmind value renderers show what an enrichment module answered, never
 * saved and so never validated: a value from the answer becomes a link only
 * when it is http(s), and is otherwise text or not shown.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/ViewTemplateHarness.php';

class ValueRendererLinkTest extends TestCase
{
    const DIR = 'Themed/Overmind/Elements/Values/Renderers/';
    const INERT = 'ftp://example.org/x';
    const HTTPS = 'https://example.org/x';

    private function render($template, array $data)
    {
        $view = new ViewTemplateHarness();
        return $view->render(self::DIR . $template, ['data' => $data]);
    }

    private function account($link)
    {
        return $this->render('account_presence_full.ctp', [
            'accounts' => [[
                'platform' => 'forum', 'handle' => 'alice-handle',
                'link' => $link, 'display' => null, 'created' => null,
                'last_login' => null, 'sources' => [],
            ]],
            'breaches' => [], 'first_breach' => null,
            'last_breach' => null, 'passwords' => false, 'exposed' => [],
        ]);
    }

    private function breach($link)
    {
        return $this->render('account_presence_full.ctp', [
            'accounts' => [],
            'breaches' => [[
                'link' => $link, 'title' => 'Acme breach', 'name' => 'acme',
                'verified' => null, 'domain' => null, 'at' => null,
                'classes' => [], 'accounts' => null, 'sources' => [],
            ]],
            'first_breach' => null, 'last_breach' => null,
            'passwords' => false, 'exposed' => [],
        ]);
    }

    private function reputation($link)
    {
        return $this->render('reputation_full.ctp', [
            'split' => false, 'threat' => 0, 'benign' => 0,
            'verdicts' => [[
                'reading' => 'threat', 'classification' => 'bad',
                'score' => null, 'module' => 'mod', 'template' => 'tpl',
                'link' => $link, 'whitelisted' => false, 'riot' => false,
                'detail' => [],
            ]],
        ]);
    }

    private function capture($url)
    {
        return $this->render('page_capture_full.ctp', [
            'captures' => [[
                'url' => $url, 'domain' => null, 'captured' => null,
                'module' => 'mod', 'attachment' => null, 'archive' => [],
                'text' => null,
            ]],
        ]);
    }

    private function fileVerdict($permalink)
    {
        return $this->render('file_verdict_full.ctp', [
            'reports' => [[
                'reading' => 'threat', 'ratio' => '5/70', 'module' => 'mod',
                'verdict' => null, 'permalink' => $permalink,
                'first_submission' => null, 'last_submission' => null,
                'severity' => null, 'threat_score' => null,
                'community_score' => null, 'comment' => null,
            ]],
        ]);
    }

    private function vulnerability($reference)
    {
        return $this->render('vulnerability_full.ctp', [
            'records' => [[
                'band' => 'high', 'score' => null, 'id' => 'CVE-2000-0001',
                'state' => null, 'sources' => [], 'exploited' => [],
                'summary' => null, 'published' => null, 'modified' => null,
                'vector' => null, 'products' => [],
                'references' => [$reference],
            ]],
        ]);
    }

    public function renderers()
    {
        return [
            'account link' => ['account', 'alice-handle'],
            'breach link' => ['breach', 'Acme breach'],
            'reputation link' => ['reputation', null],
            'page capture url' => ['capture', self::INERT],
            'file verdict permalink' => ['fileVerdict', null],
            'vulnerability reference' => ['vulnerability', self::INERT],
        ];
    }

    /**
     * @dataProvider renderers
     */
    public function testOtherSchemeIsNotLinked($renderer, $text)
    {
        $html = $this->$renderer(self::INERT);

        $this->assertStringNotContainsString('href="ftp:', $html);
        $this->assertStringNotContainsString('href="' . self::INERT, $html);
        if ($text !== null) {
            $this->assertStringContainsString($text, $html);
        }
    }

    /**
     * @dataProvider renderers
     */
    public function testHttpsIsLinked($renderer)
    {
        $html = $this->$renderer(self::HTTPS);

        $this->assertStringContainsString('href="' . self::HTTPS . '"', $html);
    }
}
