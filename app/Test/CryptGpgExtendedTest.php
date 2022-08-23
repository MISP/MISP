<?php
require_once __DIR__ . '/../Lib/Tools/GpgTool.php';
require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Lib/Tools/CryptGpgExtended.php';

use PHPUnit\Framework\TestCase;

class GpgToolTest extends TestCase
{
    public function testInit(): void
    {
        $gpg = $this->init();
        $this->assertInstanceOf('CryptGpgExtended', $gpg);
        $this->assertIsString($gpg->getVersion());
    }

    public function testSignAndVerify()
    {
        $gpg = $this->init();
        include __DIR__ . '/../Config/config.php';
        $gpg->addSignKey($config['GnuPG']['email'], $config['GnuPG']['password']);

        $testString = 'ahojSvete';

        $signature = $gpg->sign($testString, Crypt_GPG::SIGN_MODE_DETACHED, Crypt_GPG::ARMOR_BINARY);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());

        $signature = $gpg->sign($testString, Crypt_GPG::SIGN_MODE_DETACHED, Crypt_GPG::ARMOR_ASCII);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());

        // Tmp file
        $tmpFile = new TmpFileTool();
        $tmpFile->write($testString);
        $signature = $gpg->signFile($tmpFile, null, Crypt_GPG::SIGN_MODE_DETACHED, Crypt_GPG::ARMOR_BINARY);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());
    }

    private function init(): CryptGpgExtended
    {
        require_once 'Crypt/GPG.php';
        include __DIR__ . '/../Config/config.php';

        $options = [
            'homedir' => $config['GnuPG']['homedir'],
            'gpgconf' => $config['GnuPG']['gpgconf'] ?? null,
            'binary' => $config['GnuPG']['binary'] ?? '/usr/bin/gpg',
        ];
        return new CryptGpgExtended($options);
    }
}
