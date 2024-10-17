<?php
require_once __DIR__ . '/../Lib/Tools/ComplexTypeTool.php';

use PHPUnit\Framework\TestCase;

class ComplexTypeToolTest extends TestCase
{
    public function testCheckCSV(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $csv = <<<CSV
# Downloaded from 1.1.1.1

127.0.0.1
"127.0.0.2"
CSV;
        $results = $complexTypeTool->checkCSV($csv);
        $this->assertCount(2, $results);
    }

    public function testCheckCSVTabulator(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $csv = <<<CSV
###########################################################################################
# Downloaded from 1.1.1.1
###########################################################################################
127.0.0.1\t127.0.0.3
"127.0.0.2"
   58.214.25.190
   58.214.239.53
CSV;
        $results = $complexTypeTool->checkCSV($csv, ['delimiter' => '\t']);
        $this->assertCount(5, $results);
    }

    public function testCheckCSVValues(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $csv = <<<CSV
127.0.0.1\t127.0.0.2
127.0.0.3\t127.0.0.4
CSV;
        $results = $complexTypeTool->checkCSV($csv, ['value' => '1', 'delimiter' => '\t']);
        $this->assertCount(2, $results);
        foreach (['127.0.0.1', '127.0.0.3'] as $k => $test) {
            $this->assertEquals($test, $results[$k]['value']);
            $this->assertEquals('ip-dst', $results[$k]['default_type']);
        }
    }

    public function testCheckCSVEmpty(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkCSV('');
        $this->assertCount(0, $results);
    }

    public function testCheckCSVEmptyLines(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkCSV(",,,\t\n,,,,,");
        $this->assertCount(0, $results);
    }

    public function testCheckCSVTestFile(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkCSV(file_get_contents(__DIR__ . '/../../tests/event.csv'));
        $this->assertCount(37, $results);
    }

    public function testCheckFreeTextHeader(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $text = <<<EOT
# LAST 1000 # UTC UPDATE 2020-07-13 08:15:00
127.0.0.1,(127.0.0.2),  <127.0.0.3>; "127.0.0.4" "'127.0.0.5'"
EOT;
        $results = $complexTypeTool->checkFreeText($text);
        $this->assertCount(5, $results);
        foreach (['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5'] as $k => $test) {
            $this->assertEquals($test, $results[$k]['value']);
            $this->assertEquals('ip-dst', $results[$k]['default_type']);
        }
    }

    public function testCheckFreeTextIpv4(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('127.0.0.1');
        $this->assertCount(1, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextIpv4Bracket(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('we also saw an IP address (8.8.8.8).');
        $this->assertCount(1, $results);
        $this->assertEquals('8.8.8.8', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextIpv4WithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('127.0.0.1:8080');
        $this->assertCount(1, $results);
        $this->assertEquals('127.0.0.1|8080', $results[0]['value']);
        $this->assertEquals('ip-dst|port', $results[0]['default_type']);
        $this->assertEquals('On port 8080', $results[0]['comment']);
    }

    public function testCheckFreeTextIpv4Cidr(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('127.0.0.1/32');
        $this->assertCount(1, $results);
        $this->assertEquals('127.0.0.1/32', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/6009
    public function testCheckFreeTextIpv6(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('2a00:1450:4005:80a::2003');
        $this->assertCount(1, $results);
        $this->assertEquals('2a00:1450:4005:80a::2003', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/3383
    public function testCheckFreeTextIpv6Invalid(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('fe80:0000:f2cd:7d80:3f37:52c6');
        $this->assertCount(0, $results);
    }

    public function testCheckFreeTextIpv6Cidr(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('2a00:1450:4005:80a::2003/128');
        $this->assertCount(1, $results);
        $this->assertEquals('2a00:1450:4005:80a::2003/128', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextIpv6WithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('[1fff:0:a88:85a3::ac1f]:8001');
        $this->assertCount(1, $results);
        $this->assertEquals('1fff:0:a88:85a3::ac1f|8001', $results[0]['value']);
        $this->assertEquals('ip-dst|port', $results[0]['default_type']);
        $this->assertEquals('On port 8001', $results[0]['comment']);
    }

    public function testCheckFreeTextDomain(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('example.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainThirdLevel(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('example.example.com', $results[0]['value']);
        $this->assertEquals('hostname', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainDot(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.com.');
        $this->assertCount(1, $results);
        $this->assertEquals('example.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainNotExistsTld(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $complexTypeTool->setTLDs(['com']);
        $results = $complexTypeTool->checkFreeText('example.example');
        $this->assertCount(1, $results);
        $this->assertEquals('example.example', $results[0]['value']);
        $this->assertEquals('filename', $results[0]['default_type']);
    }

    public function testCheckFreeTextFilenameMultipleExt(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.txt.zip');
        $this->assertCount(1, $results);
        $this->assertEquals('example.txt.zip', $results[0]['value']);
        $this->assertEquals('filename', $results[0]['default_type']);
    }

    public function testCheckFreeTextFilenameWithPathUnix(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('/var/log/example.txt.zip');
        $this->assertCount(1, $results);
        $this->assertEquals('/var/log/example.txt.zip', $results[0]['value']);
        $this->assertEquals('filename', $results[0]['default_type']);
    }

    public function testCheckFreeTextFilenameWithPathWindows(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('C:\example.txt.zip');
        $this->assertCount(1, $results);
        $this->assertEquals('C:\example.txt.zip', $results[0]['value']);
        $this->assertEquals('filename', $results[0]['default_type']);
    }

    public function testCheckFreeTextRegkey(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion');
        $this->assertCount(1, $results);
        $this->assertEquals('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion', $results[0]['value']);
        $this->assertEquals('regkey', $results[0]['default_type']);
    }

    public function testCheckFreeTextDomainWithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('example.com:80');
        $this->assertCount(1, $results);
        $this->assertEquals('example.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
        $this->assertEquals('On port 80', $results[0]['comment']);
    }

    public function testCheckFreeTextDomainUppercase(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('EXAMPLE.COM');
        $this->assertCount(1, $results);
        $this->assertEquals('EXAMPLE.COM', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    public function testCheckFreeTextIdnDomain(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('háčkyčárky.cz');
        $this->assertCount(1, $results);
        $this->assertEquals('háčkyčárky.cz', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/657
    public function testCheckFreeTextPunycode(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('xn--ghq549cb2anjl2suxo.com');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--ghq549cb2anjl2suxo.com', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/657
    public function testCheckFreeTextPunycodeTld(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $complexTypeTool->setTLDs(['xn--fiqs8s']);
        $results = $complexTypeTool->checkFreeText('xn--lbrs59br5a.xn--fiqs8s');
        $this->assertCount(1, $results);
        $this->assertEquals('xn--lbrs59br5a.xn--fiqs8s', $results[0]['value']);
        $this->assertEquals('domain', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/3580
    public function testCheckFreeTextDate(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('2018-08-21');
        $this->assertCount(0, $results);
    }

    public function testCheckFreeTextEmail(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test@example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    public function testCheckFreeTextEmailBracket(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test[@]example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/4805
    public function testCheckFreeTextEmailBracketAt(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('test[at]example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('test@example.com', $results[0]['value']);
        $this->assertEquals('email-src', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlHttp(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('http://example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('http://example.com', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlHttps(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('https://example.com');
        $this->assertCount(1, $results);
        $this->assertEquals('https://example.com', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlWithPort(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('https://github.com:443/MISP/MISP');
        $this->assertCount(1, $results);
        $this->assertEquals('https://github.com:443/MISP/MISP', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlWithoutProtocol(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('github.com/MISP/MISP');
        $this->assertCount(1, $results);
        $this->assertEquals('github.com/MISP/MISP', $results[0]['value']);
        $this->assertEquals('url', $results[0]['default_type']);
    }

    public function testCheckFreeTextUrlVirusTotal(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('https://www.virustotal.com/example https://virustotal.com/example');
        $this->assertCount(2, $results);

        $this->assertEquals('https://www.virustotal.com/example', $results[0]['value']);
        $this->assertEquals('link', $results[0]['default_type']);

        $this->assertEquals('https://virustotal.com/example', $results[1]['value']);
        $this->assertEquals('link', $results[1]['default_type']);
    }

    public function testCheckFreeTextUrlHybridAnalysis(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('https://www.hybrid-analysis.com/example');
        $this->assertCount(1, $results);
        $this->assertEquals('https://www.hybrid-analysis.com/example', $results[0]['value']);
        $this->assertEquals('link', $results[0]['default_type']);
    }

    // Issue https://github.com/MISP/MISP/issues/4908
    public function testCheckFreeTextUrlReplace(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['hxxp://example.com', 'hxtp://example.com', 'htxp://example.com'] as $test) {
            $results = $complexTypeTool->checkFreeText($test);
            $this->assertCount(1, $results);
            $this->assertEquals('http://example.com', $results[0]['value']);
            $this->assertEquals('url', $results[0]['default_type']);
        }
    }

    // Issue https://github.com/MISP/MISP/issues/4908
    public function testCheckFreeTextUrlReplaceHttps(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['hxxps://example.com', 'hxtps://example.com', 'htxps://example.com'] as $test) {
            $results = $complexTypeTool->checkFreeText($test);
            $this->assertCount(1, $results);
            $this->assertEquals('https://example.com', $results[0]['value']);
            $this->assertEquals('url', $results[0]['default_type']);
        }
    }

    public function testCheckFreeTextBtc(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa');
        $this->assertCount(1, $results);
        $this->assertEquals('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', $results[0]['value']);
        $this->assertEquals('btc', $results[0]['default_type']);
    }

    public function testCheckFreeTextBtcBech32(): void
    {
        $complexTypeTool = new ComplexTypeTool();

        $validAddresses = [
            'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
            'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',
            'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
            'BC1SW50QA3JX3S',
            'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj',
            'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy',
        ];

        foreach ($validAddresses as $validAddress) {
            $results = $complexTypeTool->checkFreeText($validAddress);
            $this->assertCount(1, $results);
            $this->assertEquals($validAddress, $results[0]['value']);
            $this->assertEquals('btc', $results[0]['default_type']);
        }
    }

    public function testCheckFreeTextSsdeep(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('24:VGXGP7L5e/Ixt3af/WKPPaYpzg4m3XWMCsXNCRs0:kYDxcfPZpelCs9Cm0');
        $this->assertCount(1, $results);
        $this->assertEquals('24:VGXGP7L5e/Ixt3af/WKPPaYpzg4m3XWMCsXNCRs0:kYDxcfPZpelCs9Cm0', $results[0]['value']);
        $this->assertEquals('ssdeep', $results[0]['default_type']);
    }

    public function testCheckFreeTextCve(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('CVE-2019-16202');
        $this->assertCount(1, $results);
        $this->assertEquals('CVE-2019-16202', $results[0]['value']);
        $this->assertEquals('vulnerability', $results[0]['default_type']);
    }

    public function testCheckFreeTextCveLowercase(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('cve-2019-16202');
        $this->assertCount(1, $results);
        $this->assertEquals('CVE-2019-16202', $results[0]['value']);
        $this->assertEquals('vulnerability', $results[0]['default_type']);
    }

    public function testCheckFreeTextAs(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('as0 AS0');
        $this->assertCount(1, $results);
        $this->assertEquals('AS0', $results[0]['value']);
        $this->assertEquals('AS', $results[0]['default_type']);
    }

    public function testCheckFreeTextMd5(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('9e107d9d372bb6826bd81d3542a419d6');
        $this->assertCount(1, $results);
        $this->assertEquals('9e107d9d372bb6826bd81d3542a419d6', $results[0]['value']);
        $this->assertEquals('md5', $results[0]['default_type']);
    }

    public function testCheckFreeTextMd5Uppercase(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('9E107D9D372BB6826BD81D3542A419D6');
        $this->assertCount(1, $results);
        $this->assertEquals('9E107D9D372BB6826BD81D3542A419D6', $results[0]['value']);
        $this->assertEquals('md5', $results[0]['default_type']);
    }

    public function testCheckFreeTextSha1(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('da39a3ee5e6b4b0d3255bfef95601890afd80709');
        $this->assertCount(1, $results);
        $this->assertEquals('da39a3ee5e6b4b0d3255bfef95601890afd80709', $results[0]['value']);
        $this->assertEquals('sha1', $results[0]['default_type']);
    }

    public function testCheckFreeTextFilenameWithMd5(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('ahoj.txt|9e107d9d372bb6826bd81d3542a419d6');
        $this->assertCount(1, $results);
        $this->assertEquals('ahoj.txt|9e107d9d372bb6826bd81d3542a419d6', $results[0]['value']);
        $this->assertEquals('filename|md5', $results[0]['default_type']);
    }

    public function testCheckFreeTextRandomString(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('cK753n3MVw');
        $this->assertCount(0, $results);
    }

    public function testCheckFreeTextEmpty(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('');
        $this->assertCount(0, $results);
    }

    public function testCheckFreeTextEmptyValues(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['|', '&', '$', '0', ':80', '1.2', '[]:80', '\.', '.', ':', 'a:b', 'a:b:c'] as $char) {
            $results = $complexTypeTool->checkFreeText($char);
            $this->assertCount(0, $results);
        }
    }

    public function testCheckFreeTextNonBreakableSpace(): void
    {
        $complexTypeTool = new ComplexTypeTool();

        $results = $complexTypeTool->checkFreeText("127.0.0.1\xc2\xa0127.0.0.2");
        $this->assertCount(2, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);

        $results = $complexTypeTool->checkFreeText("127.0.0.1\xc2\xa0\xc2\xa0127.0.0.2");
        $this->assertCount(2, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextControlCharToSpace(): void
    {
        $complexTypeTool = new ComplexTypeTool();

        $results = $complexTypeTool->checkFreeText("127.0.0.1\x1d127.0.0.2");
        $this->assertCount(2, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);

        $results = $complexTypeTool->checkFreeText("127.0.0.1\x1d\x1d127.0.0.2");
        $this->assertCount(2, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextQuoted(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('="127.0.0.1",="127.0.0.2","","1"');
        $this->assertCount(2, $results);
        $this->assertEquals('127.0.0.1', $results[0]['value']);
        $this->assertEquals('ip-dst', $results[0]['default_type']);
    }

    public function testCheckFreeTextRemoveDuplicates(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        $results = $complexTypeTool->checkFreeText('1.2.3.4 1.2.3.4');
        $this->assertCount(1, $results);
    }

    public function testRefangValueUrl(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['meow://example.com', 'h[tt]p://example.com'] as $test) {
            $this->assertEquals('http://example.com', $complexTypeTool->refangValue($test, 'url'));
            $this->assertEquals('http://example.com', $complexTypeTool->refangValue($test, 'link'));
        }
    }

    public function testRefangValueDot(): void
    {
        $complexTypeTool = new ComplexTypeTool();
        foreach (['127.0.0.1', '127[.]0.0.1', '127[.]0[.]0[.]1', '127[dot]0[dot]0[dot]1', '127(dot)0(dot)0(dot)1'] as $test) {
            $this->assertEquals('127.0.0.1', $complexTypeTool->refangValue($test, 'ip-src'));
        }
    }

    // see #7214
    public function testRefangKeepBackslashes(): void
    {
        $text = 'http://googlechromeupdater.twilightparadox.com/html?DVXNSTHORF=fd6f240590734406be3bd35ca3622ea0;GRIBOOZ0LN=a3bf23855b0b40dda08f709fabb60d32;\..\..\..\./mshtml,RunHTMLApplication';
        $complexTypeTool = new ComplexTypeTool();
        $this->assertEquals($text, $complexTypeTool->refangValue($text, 'url'));
    }

    // Issue https://github.com/MISP/MISP/pull/9989
    public function testRefangEmailBrackets(): void
    {
        $toCheck = [
            'admin@admin[.]test',
            'admin[@]admin[.]test',
            'admin[at]admin[dot]test',
        ];

        foreach ($toCheck as $test) {
            $this->assertEquals('admin@admin.test', ComplexTypeTool::refangValue($test, 'email-src'));
        }
    }
}
