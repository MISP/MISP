<?php

namespace App\Test\TestCase\Tool;

use App\Lib\Tools\CryptGpgExtended;
use App\Lib\Tools\SendEmail;
use Cake\Core\Configure;
use Cake\TestSuite\EmailTrait;
use Cake\TestSuite\TestCase;
use Cake\TestSuite\TestEmailTransport;

class SendEmailTest extends TestCase
{
    # see: https://book.cakephp.org/4/en/core-libraries/email.html#testing-mailers
    # this trait prevents the emails from actually being sent (won't reach MailHog)
    use EmailTrait;

    public function testSendPlaintextEmailToUserEncryptedByGpg()
    {
        $gpgkey = file_get_contents('/var/www/html/webroot/gpg.asc');
        $to = 'admin@admin.test';
        $user = [
            'email' => $to,
            'gpgkey' => $gpgkey,
            'certif_public' => null
        ];

        $subject = 'Test (GPG Encrypted)';
        $body = 'Test Encrypted Body';
        $bodyNoEnc = false;

        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);

        $sendEmail->sendToUser($user, $subject, $body, $bodyNoEnc);

        $this->assertMailSentTo($to);
        $this->assertMailSubjectContains($subject);

        $messages = TestEmailTransport::getMessages();
        $this->assertCount(1, $messages);

        $rawEmailBody = $messages[0]->getBodyString();

        # decrypt message
        $decrypted = $gpg->decrypt($rawEmailBody);
        $this->assertIsString($decrypted);
        $this->assertStringContainsString($body, $decrypted);
    }

    public function testSendPlaintextEmailToUserSignedByGpg()
    {
        $to = 'admin@admin.test';
        $user = [
            'email' => $to,
            'gpgkey' => null,
            'certif_public' => null
        ];

        $subject = 'Test (PGP Signed)';
        $body = 'Test Signed Body';
        $bodyNoEnc = true;

        $gpg = $this->initializeGpg();
        $sendEmail = new SendEmail($gpg);

        $sendEmail->sendToUser($user, $subject, $body, $bodyNoEnc);

        $this->assertMailSentTo($to);

        $messages = TestEmailTransport::getMessages();
        $this->assertCount(1, $messages);

        $rawBodyArray = $messages[0]->getBody();
        $rawEmailBody = $messages[0]->getBodyText();

        # get signature from email body
        $pattern = '/-----BEGIN PGP SIGNATURE-----\s(.*?\s)*?-----END PGP SIGNATURE-----/s';
        if (preg_match($pattern, $rawEmailBody, $matches)) {
            $signature = $matches[0];
        } else {
            $this->fail('PGP signature not found in the email body');
        }

        # get body without signature
        $boundry = $rawBodyArray[0];
        $parts = [];
        foreach ($rawBodyArray as $line) {
            if ($line === $boundry) {
                $parts[] = '';
            } else {
                $parts[count($parts) - 1] .= $line . "\r\n";
            }
        }
        $rawEmailBody = $parts[0] . "\r\n";

        // TODO: verify signature properly, the email body line breaks are modified by CakePHP (Message::getBodyString()) and breaks the signature verification

        $verified = $gpg->verify($rawEmailBody, $signature);
        $this->assertIsString($signature);
        $this->assertIsArray($verified);
        $this->assertCount(1, $verified);
        $this->assertTrue($verified[0]->isValid());
    }

    private function initializeGpg(): CryptGpgExtended
    {
        $config = Configure::read('GnuPG');

        return new CryptGpgExtended($config);
    }
}
