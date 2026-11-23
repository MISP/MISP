<?php
/**
 * Protected event signatures: the exact-byte signature header, the refusal of
 * a whitespace-stripped signature for a body that carries the version marker,
 * and the headers a sender emits per peer version.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database. Framework classes are
 * stubbed below, each guarded so that a full-suite run sharing one process
 * keeps whichever stub loaded first. Signing and verification use the gpg
 * CLI against a throw-away homedir.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

require_once __DIR__ . '/../Lib/Tools/JsonTool.php';
require_once __DIR__ . '/../Lib/Tools/CryptGpgExtended.php';
require_once __DIR__ . '/../Lib/Tools/GpgTool.php';
require_once __DIR__ . '/../Model/CryptographicKey.php';

class ProtectedEventSignatureLog
{
    public $messages = array();

    public function createLogEntry($user, $action, $model, $id, $message)
    {
        $this->messages[] = $message;
    }
}

/**
 * The instance key and gpg handle come from the test homedir directly, so the
 * result does not depend on which Configure stub the process loaded.
 */
class ProtectedEventSignatureKey extends CryptographicKey
{
    public static $homedir;
    public static $email;
    public $fakeLog;
    private $testGpg;

    public function __construct()
    {
        $this->fakeLog = new ProtectedEventSignatureLog();
    }

    protected function loadLog()
    {
        return $this->fakeLog;
    }

    public function getGpg()
    {
        if (!$this->testGpg) {
            $this->testGpg = new CryptGpgExtended([
                'homedir' => self::$homedir,
                'binary' => '/usr/bin/gpg',
            ]);
        }
        return $this->testGpg;
    }

    public function ingestInstanceKey()
    {
        $keys = $this->getGpg()->getKeys(self::$email);
        if (empty($keys)) {
            return false;
        }
        $this->getGpg()->addSignKey($keys[0], '');
        return $keys[0]->getPrimaryKey()->getFingerprint();
    }
}

class ProtectedEventExactSignatureTest extends TestCase
{
    private static $homedir;
    private static $listed = array();
    private static $unlisted = array();

    /** @var ProtectedEventSignatureKey */
    private $model;

    public static function setUpBeforeClass(): void
    {
        $gpg = trim((string)shell_exec('command -v gpg 2>/dev/null'));
        if ($gpg === '') {
            self::markTestSkipped('gpg is not available.');
        }
        self::$homedir = sys_get_temp_dir() . '/misp-sig-test-' . bin2hex(random_bytes(6));
        mkdir(self::$homedir, 0700);
        self::$listed = self::generateKey('listed@example.test');
        self::$unlisted = self::generateKey('unlisted@example.test');
        ProtectedEventSignatureKey::$homedir = self::$homedir;
        ProtectedEventSignatureKey::$email = self::$listed['email'];
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$homedir && is_dir(self::$homedir)) {
            shell_exec('gpgconf --homedir ' . escapeshellarg(self::$homedir) . ' --kill all 2>/dev/null');
            shell_exec('rm -rf ' . escapeshellarg(self::$homedir));
        }
    }

    protected function setUp(): void
    {
        $this->model = new ProtectedEventSignatureKey();
    }

    private static function gpgCommand($args)
    {
        return 'gpg --homedir ' . escapeshellarg(self::$homedir) . ' --batch --pinentry-mode loopback --passphrase "" ' . $args . ' 2>&1';
    }

    private static function generateKey($email)
    {
        exec(self::gpgCommand('--quick-gen-key ' . escapeshellarg($email) . ' ed25519 sign never'), $out, $code);
        if ($code !== 0) {
            self::fail("Key generation failed: " . implode("\n", $out));
        }
        $armored = shell_exec(self::gpgCommand('--armor --export ' . escapeshellarg($email)));
        $fpr = trim((string)shell_exec(
            'gpg --homedir ' . escapeshellarg(self::$homedir) . ' --with-colons --fingerprint ' . escapeshellarg($email) .
            ' 2>/dev/null | awk -F: \'/^fpr/ {print $10; exit}\''
        ));
        return array('email' => $email, 'public' => $armored, 'fingerprint' => $fpr);
    }

    /** Binary detached signature of $data by $key, base64 encoded. */
    private static function sign($data, array $key)
    {
        $in = tempnam(sys_get_temp_dir(), 'sigin');
        $out = $in . '.sig';
        file_put_contents($in, $data);
        exec(self::gpgCommand('-u ' . escapeshellarg($key['fingerprint']) . ' --detach-sign -o ' . escapeshellarg($out) . ' ' . escapeshellarg($in)), $o, $code);
        $sig = $code === 0 ? file_get_contents($out) : false;
        @unlink($in);
        @unlink($out);
        if ($sig === false) {
            self::fail('Signing failed: ' . implode("\n", $o));
        }
        return base64_encode($sig);
    }

    private static function gpgVerifies($data, $base64Signature)
    {
        $in = tempnam(sys_get_temp_dir(), 'verin');
        $sig = $in . '.sig';
        file_put_contents($in, $data);
        file_put_contents($sig, base64_decode($base64Signature));
        exec(self::gpgCommand('--verify ' . escapeshellarg($sig) . ' ' . escapeshellarg($in)), $o, $code);
        @unlink($in);
        @unlink($sig);
        return $code === 0;
    }

    private static function strip($data)
    {
        return preg_replace("/\s+/", "", $data);
    }

    private static function body(array $overrides = array(), $marker = true)
    {
        $event = array(
            'uuid' => '5f0b2d38-6c1c-4a39-a5de-0d2f0a1b2c3d',
            'info' => 'Protected event',
            'protected' => true,
            'Tag' => array(array('name' => 'tlp:amber')),
            'Attribute' => array(array(
                'uuid' => '6a1c3e48-1a2b-4c3d-8e9f-0a1b2c3d4e5f',
                'type' => 'comment',
                'value' => 'free text value',
                'comment' => 'a comment',
            )),
            'CryptographicKey' => array(array('type' => 'pgp', 'key_data' => self::$listed['public'])),
        );
        if ($marker) {
            $event = array_slice($event, 0, 3, true) + array('signature_version' => 2) + array_slice($event, 3, null, true);
        }
        return json_encode(array('Event' => array_replace_recursive($event, $overrides)), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    private static function eventFor(array $key, $revoked = 0)
    {
        return array('Event' => array(
            'uuid' => '5f0b2d38-6c1c-4a39-a5de-0d2f0a1b2c3d',
            'CryptographicKey' => array(array('key_data' => $key['public'], 'revoked' => $revoked)),
        ));
    }

    private function validate($body, $legacy, $exact, $revoked = 0)
    {
        return $this->model->validateProtectedEvent($body, array('id' => 1), $legacy, self::eventFor(self::$listed, $revoked), $exact);
    }

    public function testExactSignatureOverUntouchedBodyWithMarkerIsAccepted()
    {
        $body = self::body();
        $this->assertSame(self::$listed['fingerprint'], $this->validate($body, null, self::sign($body, self::$listed)));
    }

    public function testExactSignatureRejectsWhitespaceInsertedInsideFreeText()
    {
        $body = self::body();
        $signature = self::sign($body, self::$listed);
        $legacy = self::sign(self::strip($body), self::$listed);
        $tampered = str_replace('tlp:amber', 'tlp:amb er', $body);
        $this->assertNotSame($body, $tampered);
        $this->assertFalse($this->validate($tampered, $legacy, $signature));
    }

    public function testInvalidExactSignatureIsNotRescuedByValidLegacySignature()
    {
        $body = self::body();
        $legacy = self::sign(self::strip($body), self::$listed);
        $this->assertFalse($this->validate($body, $legacy, self::sign($body, self::$unlisted)));
        $this->assertFalse($this->validate($body, $legacy, base64_encode('garbage')));
    }

    public function testLegacySignatureAloneIsRefusedWhenBodyCarriesTheMarker()
    {
        $body = self::body();
        $this->assertFalse($this->validate($body, self::sign(self::strip($body), self::$listed), null));
        $this->assertContains(
            'The event was signed over its exact bytes, but that signature is missing.',
            $this->model->fakeLog->messages
        );
    }

    public function testLegacySignatureAloneIsAcceptedWithoutMarkerAsSentByOlderInstances()
    {
        $body = self::body(array(), false);
        $this->assertSame(self::$listed['fingerprint'], $this->validate($body, self::sign(self::strip($body), self::$listed), null));
    }

    public function testLegacyWithoutMarkerStillAcceptsWhitespaceInsertedIntoFreeTextResidualOfOlderSignedData()
    {
        $body = self::body(array(), false);
        $legacy = self::sign(self::strip($body), self::$listed);
        $tampered = str_replace('tlp:amber', 'tlp:amb er', $body);
        $this->assertNotSame($body, $tampered);
        $this->assertSame(self::$listed['fingerprint'], $this->validate($tampered, $legacy, null));
    }

    public function testLegacyRefusesWhitespaceInsertedIntoTheMarkerKey()
    {
        $body = self::body();
        $legacy = self::sign(self::strip($body), self::$listed);
        $tampered = str_replace('"signature_version"', '"signature_ version"', $body);
        $this->assertNotSame($body, $tampered);
        $this->assertFalse($this->validate($tampered, $legacy, null));
    }

    public function testExactSignatureSkipsTheWhitespaceScanOnIdentifiers()
    {
        $body = self::body(array('Attribute' => array(array('uuid' => ' 6a1c3e48-1a2b-4c3d-8e9f-0a1b2c3d4e5f'))));
        $this->assertStringContainsString('" 6a1c3e48', $body);
        $this->assertSame(self::$listed['fingerprint'], $this->validate($body, null, self::sign($body, self::$listed)));
    }

    public function testExactSignatureByRevokedKeyIsRefused()
    {
        $body = self::body();
        $this->assertFalse($this->validate($body, null, self::sign($body, self::$listed), 1));
    }

    public function testSignatureHeadersCarryTheSignaturesEachPeerVersionNeeds()
    {
        $data = self::body();
        $this->assertNotSame($data, self::strip($data));

        $both = $this->model->signatureHeaders($data, null);
        $this->assertSame(array('x-pgp-signature', 'x-pgp-signature-v2'), array_keys($both));
        $this->assertTrue(self::gpgVerifies(self::strip($data), $both['x-pgp-signature']));
        $this->assertFalse(self::gpgVerifies($data, $both['x-pgp-signature']));
        $this->assertTrue(self::gpgVerifies($data, $both['x-pgp-signature-v2']));
        $this->assertFalse(self::gpgVerifies(self::strip($data), $both['x-pgp-signature-v2']));

        $new = $this->model->signatureHeaders($data, '3.0.0');
        $this->assertSame(array('x-pgp-signature-v2'), array_keys($new));
        $this->assertTrue(self::gpgVerifies($data, $new['x-pgp-signature-v2']));
        $this->assertFalse(self::gpgVerifies(self::strip($data), $new['x-pgp-signature-v2']));

        $old = $this->model->signatureHeaders($data, '2.5.52');
        $this->assertSame(array('x-pgp-signature'), array_keys($old));
        $this->assertTrue(self::gpgVerifies(self::strip($data), $old['x-pgp-signature']));
        $this->assertFalse(self::gpgVerifies($data, $old['x-pgp-signature']));
    }
}
