<?php

namespace App\Test\TestCase\Tool;

use App\Lib\Tools\HttpTool;
use Cake\Core\Configure;
use Cake\Http\Client\Exception\NetworkException;
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

    public function testGoogle($options=[])
    {
        $client = new HttpTool($options);
        $response = $client->get('https://www.google.com');
        $this->assertTrue($response->isOk());
    }

    public function testSelfSigned()
    {
        $config = [
            'self_signed' => true
        ];
        $client = new HttpTool($config);
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
    }

    public function testSelfSignedFail()
    {
        $config = [
            'ssl_verify_peer' => true,
            'ssl_verify_host' => false];

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
        // write CA file to disk, load it from there
        $fname = '/tmp/ca.pem';
        $certfile = new \SplFileObject($fname, "w+");
        $certfile->fwrite(self::HTTPS_SELF_SIGNED_CA);
        $config = ['ssl_cafile' => $fname];
        $client = new HttpTool($config);
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
        unlink($fname);
    }

    public function testSelfSignedCustomSystemCa()
    {
        // write CA file to disk, load it from there
        $fname = '/tmp/ca.pem';
        $certfile = new \SplFileObject($fname, "w+");
        $certfile->fwrite(self::HTTPS_SELF_SIGNED_CA);
        Configure::write('MISP.ca_path', $fname);
        $client = new HttpTool();
        $response = $client->get(self::HTTPS_SELF_SIGNED_URI);
        $this->assertTrue($response->isOk());
        unlink($fname);
    }

    public function testProxy()
    {
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
        Configure::write('Proxy.port', 1234);  // bad port
        $this->testGoogle(['skip_proxy' => true]);
    }

    public function testParseCertificate()
    {
        $certificate = self::HTTPS_SELF_SIGNED_CA;
        $result = HttpTool::parseCertificate($certificate);

        $this->assertArrayHasKey('serial_number', $result);
        // $what_it_should_be = [
        //     'serial_number' => '6B0792551E9BBE18988F9B115465A83D8A4B445E'
        //     'signature_type' => 'RSA-SHA256'
        //     'valid_from' => Cake\I18n\FrozenTime Object &000000000000015f0000000000000000 (
        //         'date' => '2023-12-18 18:45:31.000000'
        //         'timezone_type' => 1
        //         'timezone' => '+00:00'
        //     )
        //     'valid_to' => Cake\I18n\FrozenTime Object &00000000000001600000000000000000 (
        //         'date' => '2026-09-12 18:45:31.000000'
        //         'timezone_type' => 1
        //         'timezone' => '+00:00'
        //     )
        //     'public_key_size' => 4096
        //     'public_key_type' => 'RSA'
        //     'public_key_size_ok' => true
        //     'valid_from_ok' => true
        //     'valid_to_ok' => true
        //     'subject' => 'C=LU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=172.16.40.133'
        //     'issuer' => 'C=LU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=172.16.40.133'
        // ];
        // debug($result);
        // $this->assertTrue(array_diff($result, $what_it_should_be));
    }

    public function testFetchCertificate()
    {
        $client = new HttpTool();
        $certificates = $client->fetchCertificates('https://www.google.com');
        // $certificates = $client->fetchCertificates(self::HTTPS_SELF_SIGNED_URI);
        // $certificates = $client->fetchCertificates('http://www.google.com');
        
    }
}
