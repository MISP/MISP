<?php

namespace App\Test\TestCase\Tool;

use App\Lib\Tools\CryptGpgExtended;
use App\Lib\Tools\TmpFileTool;
use Cake\TestSuite\TestCase;
use Cake\Core\Configure;

// use PHPUnit\Framework\TestCase;

class CryptGpgExtendedTest extends TestCase
{
    public function testInit(): void
    {
        $gpg = $this->init();
        $this->assertInstanceOf('App\Lib\Tools\CryptGpgExtended', $gpg);
        $this->assertIsString($gpg->getVersion());
    }

    public function testSignAndVerify()
    {
        $gpg = $this->init();
        $config = Configure::read('GnuPG');

        $gpg->addSignKey($config['email'], $config['password']);

        $testString = 'ahojSvete';

        $signature = $gpg->sign($testString, \Crypt_GPG::SIGN_MODE_DETACHED, \Crypt_GPG::ARMOR_BINARY);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());

        $signature = $gpg->sign($testString, \Crypt_GPG::SIGN_MODE_DETACHED, \Crypt_GPG::ARMOR_ASCII);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());

        // Tmp file
        $tmpFile = new TmpFileTool();
        $tmpFile->write($testString);
        $signature = $gpg->signFile($tmpFile, null, \Crypt_GPG::SIGN_MODE_DETACHED, \Crypt_GPG::ARMOR_BINARY);
        $this->assertIsString($signature);

        $verified = $gpg->verify($testString, $signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());
    }

    private function init(): CryptGpgExtended
    {
        $config = Configure::read('GnuPG');

        $options = [
            'homedir' => $config['homedir'],
            'gpgconf' => $config['gpgconf'] ?? null,
            'binary' => $config['binary'] ?? '/usr/bin/gpg',
        ];

        return new CryptGpgExtended($options);
    }
}
