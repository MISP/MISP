<?php
declare(strict_types=1);

namespace App\Test\TestCase\Tool;

use App\Lib\Tools\HttpTool;
use Cake\Core\Configure;
use Cake\Http\Client\Exception\NetworkException;
use Cake\I18n\FrozenTime;
use Cake\TestSuite\TestCase;

class HttpToolTest extends TestCase
{
    protected const PROXY_SERVER = '127.0.0.1';
    protected const PROXY_USER = 'proxyuser';
    protected const PROXY_PASSWORD = 'proxypassword';
    protected const PROXY_PORT = 8888;
    protected const HTTPS_SELF_SIGNED_URI = 'https://172.16.40.133';
    protected const HTTPS_SELF_SIGNED_CA = "-----BEGIN CERTIFICATE-----
MIIFQTCCAykCFGsHklUem74YmI+bEVRlqD2KS0ReMA0GCSqGSIb3DQEBCwUAMF0x
CzAJBgNVBAYTAkxVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQxFjAUBgNVBAMMDTE3Mi4xNi40MC4xMzMwHhcN
MjMxMjE4MTg0NTMxWhcNMjYwOTEyMTg0NTMxWjBdMQswCQYDVQQGEwJMVTETMBEG
A1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkg
THRkMRYwFAYDVQQDDA0xNzIuMTYuNDAuMTMzMIICIjANBgkqhkiG9w0BAQEFAAOC
Ag8AMIICCgKCAgEA1RaPUfi/O2nyf4CSoMJAmj9C8++heh7s2OjlAWeavCUc5bqC
bBjp02UC+7bS43SaRp0XMRNvnv9Zp33JRPblSVVYDjCCn7M9IS2T6CrpIy69EB9h
SlNlEXc2XQrmxQyExV6FLPXEZaADmX2DN2CM9+MntFhTupZUqzO+SwszscN9NUVY
uYsEuvFxyqrb0P5GqfqT6C/w6UnhBiIWZJIQDGQ+200qGl+eUY3rnM4sM1TwMGpk
mdXPOEvo+qQItivIGmUIDJtwrEH/rsBVgyEfgd53ESfr1J43eEG7DzWGjTQN73DQ
rPeT4Bja6VHKAYj7e+GZexZ1okeDtHejAeiPLa9lgJ8YuUnsCl8bGgMOF+K90mYW
rwQpNjkZgL8TAGQpop5s9oF3UkkGV7ftONnZ9MMphjmfvNWDOs2gLx4imzEi89Gv
xBFtZIHwUAgeFYZOC+nuXrRJX4V/apwtCzQaVx+VXWLHWvBdAYFWdru7HNchrlMm
GgbfFxnFL3qt4rm/EOTsnqG3gWZWuqUz2tYWIF79mFrKxUOmjpTp/N1KmlQh2Pj3
iRovZDu4SFB8Hv1fvfnefdxCCy+/w0sQ4ZPJ2rq2BxrT1bhdOfFtIbagtyvNXSgX
jrTfwAwvxyaftrQNYz849k7uKBYXLboZLxQ6SJ2QYS481keQBQw0KtbE680CAwEA
ATANBgkqhkiG9w0BAQsFAAOCAgEAEYeqFlIie6U6Qm21lhUfIT29JKTv9Q+3xC3W
d/X7hSxZ1qJ0BImAwLiA0DlBkgQBE6FSSSs0XIVxNG6TvXcCXFSJl219L+SD8GuS
jV+m7Xee0YXFxulzJsFQ3oSn2AuMx+7EnfKiQXtnga3lGlXpGuPS9HDHtoUP7C6x
0JkORYtK1y411UKCY0COGh03P8ETc/LnbH0jCIGUUIiD2K3pR0R/ieX8AAE5995g
QbEdz0MpLQz5xSRcFq7sMzoELn0jj5l6wJcDihoshqeIfb0vdPbKy/CoMTAeM81f
txq2dvNjPYY1dyK9fY8BsSt98dxtrrbB9WHfxzkqbZ82KbonRoatk/TuPTTr/8TW
atRvZsvW2hXTIQnZFxZImdpxnvkl5go7d/s3Iy6nliufzMJmMNke3iIkF6HrXFIs
Hh8Ph9g2NRrfuOQJuycG7JruDz29ri3miY/o+qGSA5fS7z8gfDwnUv8yCqJ2eCun
dh2QsJfDxjG3qIFc7+CMvbghWWOZyiR6KEIWMiXUVyTuSTZiu7J7fKSzY2WgVZOs
DCOxcbMAf9SzhYlcJBfjJyN5tosRd48yyKOCeiRDsBVD2z9v9DzjBokhEKRmkgmo
ofGFNygudATRXLEQwEZmQzl2NzeYDdg6EWvOnkjnmW6+gJ++Y8FEvqQKFzD/Jvwn
xWV4oBk=
-----END CERTIFICATE-----
    ";

    public function testGoogle($options = [])
    {
        $client = new HttpTool($options);
        $response = $client->get('https://www.google.com');
        $this->assertTrue($response->isOk());
    }

    public function testSelfSigned()
    {
        $this->markTestSkipped('This is not implemented yet. Need to figure out how to connect to a self signed server for the testing.');

        $config = [
            'self_signed' => true,
        ];
        $client = new HttpTool($config);
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
    }

    public function testSelfSignedFail()
    {
        $this->markTestSkipped('This is not implemented yet. Need to figure out how to connect to a self signed server for the testing.');

        $config = [
            'ssl_verify_peer' => true,
            'ssl_verify_host' => false,

        ];

        $client = new HttpTool($config);
        try {
            $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
            $this->assertTrue(false); // always die as above should raise a self-signed cert error
        } catch (NetworkException $e) {
            $this->assertStringContainsString('SSL certificate problem: self-signed certificate', $e->getMessage(), 'Should have gotten error for self-signed certificiate.');
        }
    }

    public function testSelfSignedCustomCa()
    {
        $this->markTestSkipped('This is not implemented yet. Need to figure out how to connect to a self signed server for the testing.');

        // write CA file to disk, load it from there
        $fname = '/tmp/ca.pem';
        $certfile = new \SplFileObject($fname, 'w+');
        $certfile->fwrite(self::HTTPS_SELF_SIGNED_CA);
        $config = ['ssl_cafile' => $fname];
        $client = new HttpTool($config);
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
        unlink($fname);
    }

    public function testSelfSignedCustomSystemCa()
    {
        $this->markTestSkipped('This is not implemented yet. Need to figure out how to connect to a self signed server for the testing.');

        // write CA file to disk, load it from there
        $fname = '/tmp/ca.pem';
        $certfile = new \SplFileObject($fname, 'w+');
        $certfile->fwrite(self::HTTPS_SELF_SIGNED_CA);
        Configure::write('MISP.ca_path', $fname);
        $client = new HttpTool();
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
        unlink($fname);
    }

    public function testProxy()
    {
        $this->markTestSkipped('This is not implemented yet. Requires local proxy installation (tinyproxy) on the testing system.');
        Configure::write('Proxy.host', self::PROXY_SERVER);
        Configure::write('Proxy.port', self::PROXY_PORT);
        // Configure::write('Proxy.method', 'basic'); // auth: basic / digest
        // Configure::write('Proxy.user', self::PROXY_USER);
        // Configure::write('Proxy.password', self::PROXY_PASSWORD);
        $this->testGoogle();
        $this->testSelfSigned();
        $this->testSelfSignedFail();
        $this->testSelfSignedCustomCa();
    }

    public function testSkipProxy()
    {
        Configure::write('Proxy.host', self::PROXY_SERVER);
        Configure::write('Proxy.port', 1234); // bad port
        $this->testGoogle(['skip_proxy' => true]);
    }

    public function testParseCertificate()
    {
        $certificate = "-----BEGIN CERTIFICATE-----
        MIIEhjCCA26gAwIBAgIQMSLF87fiqdsJ4To3xUynTTANBgkqhkiG9w0BAQsFADBG
        MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
        QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzExMjAwODA5NDdaFw0yNDAyMTIw
        ODA5NDZaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYI
        KoZIzj0DAQcDQgAEMjh0kjVaHQP0RikHoIcq7BTU2pFd2rvDX0dDmPV4YsdhPzBI
        b1Ix36udTFzdP5fureCpNaucNEFoiGqex1K7JqOCAmYwggJiMA4GA1UdDwEB/wQE
        AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
        BBQ3xGOil9FWeb8g19g0kjiXUwXSUDAfBgNVHSMEGDAWgBSKdH+vhc3ulc09nNDi
        RhTzcTUdJzBqBggrBgEFBQcBAQReMFwwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3Nw
        LnBraS5nb29nL2d0czFjMzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3Jl
        cG8vY2VydHMvZ3RzMWMzLmRlcjAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAh
        BgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwGA1UdHwQ1MDMwMaAv
        oC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9mVkp4YlYtS3Rtay5jcmww
        ggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgB2/4g/Crb7lVHCYcz1h7o0tKTNuync
        aEIKn+ZnTFo6dAAAAYvr/jkgAAAEAwBHMEUCIQDvPoaGuwS/SVhLU2NRxM14RSK2
        0+rvm3ii8PXCrEqLgwIgZqR6d58UvJbFqCI6CnbJlKzARYNH2Qe/q+VYGnnRF5AA
        dQBVgdTCFpA2AUrqC5tXPFPwwOQ4eHAlCBcvo6odBxPTDAAAAYvr/jkHAAAEAwBG
        MEQCICsZCXVYTj6rAkxERKNOKVKUEwUn9AcSdATanhGFgW3uAiAPvNgBitcTLHBc
        BGtXp/3rvSK9R/O4GoWglRLWbLtnwjANBgkqhkiG9w0BAQsFAAOCAQEAfneqoNRs
        kK+9Rba3Ru8xbU3s3XGeD9WFdMY4bBs0Xkcd6YXGkMvr6zmfCPbdTTLfGA49Fc85
        kUXCQYDmoUdh9NFJS6kfRtH36DOq2fXhU47bfC6di1MIw4oBKCBhwVMQut2syBnV
        AUwkPflKgFi+5tagqpMj7Ydg5kE69Biee6wKnk4zYlvUzoBWheeYaiQNsKebcCYa
        BMtndiBl9bF3W5ShAiXYlZq/kN9B9uco0v0OdvZIH0c5vwlyVXEW6Xg8qb89p379
        y2d2fXUN6tjbZ1gE1LWMazNwkShdPvDOx1hL5MBkkhoRpUuKKfuI9Do9R57Owj14
        pmxnRfR3SsTR1w==
-----END CERTIFICATE-----
        ";
        $result = HttpTool::parseCertificate($certificate);
        // debug($result);
        $this->assertEquals($result['serial_number'], '3122C5F3B7E2A9DB09E13A37C54CA74D');
        $this->assertEquals($result['subject'], 'CN=www.google.com');
        $this->assertEquals($result['issuer'], 'C=US, O=Google Trust Services LLC, CN=GTS CA 1C3');
        $this->assertEquals($result['public_key_size_ok'], true);
        $this->assertEquals($result['valid_from_ok'], true);
        $this->assertEquals($result['valid_from'], new FrozenTime('2023-11-20 08:09:47.000000+00:00'));
        $this->assertEquals($result['valid_to'], new FrozenTime('2024-02-12 08:09:46.000000+00:00'));
        $this->assertEquals($result['signature_type'], 'RSA-SHA256');
        $this->assertEquals($result['public_key_size'], 256);
        $this->assertEquals($result['public_key_type'], 'EC (prime256v1)');
    }

    public function testFetchCertificate()
    {
        $this->markTestSkipped('This is not very well implemented yet.');
        $client = new HttpTool();
        /** @var array $certificates */
        $certificates = $client->fetchCertificates('https://www.google.com');
        // $certificates = $client->fetchCertificates(self::HTTPS_SELF_SIGNED_URI);
        // $certificates = $client->fetchCertificates('http://www.google.com');
        // we get one or more certificates from the server. No function yet to select "the right one"
        foreach ($certificates as $certificate) {
            // debug($certificate);
        }
    }
}
