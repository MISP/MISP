<?php
App::uses('CakeEmail', 'Network/Email');

class SendEmailException extends Exception {}

// RFC 4880 and 3156
// https://dkg.fifthhorseman.net/notes/inline-pgp-harmful/
// https://www.dalesandro.net/create-self-signed-smime-certificates/
class CakeEmailExtended extends CakeEmail
{
    private $body;

    public function getHeaders($include = array())
    {
        $headers = parent::getHeaders($include);

        if ($this->body instanceof MimeMultipart) {
            $headers['Content-Type'] = $this->body->getContentType();
        } else if ($this->body instanceof MessagePart) {
            $headers = array_merge($headers, $this->body->getHeaders());
        } else {
            $headers['Content-Type'] = 'multipart/mixed; boundary="' . $this->boundary() . '"';
        }

        return $headers;
    }

   public function boundary()
   {
       if ($this->body instanceof MimeMultipart) {
           return $this->body->boundary();
       }

       return $this->_boundary;
   }

    /**
     * @param string|null|MimeMultipart|MessagePart $message
     * @return $this
     */
    public function body($message = null)
    {
        if ($message === null) {
            return $this->body;
        }
        $this->body = $message;
        return $this;
    }

    /**
     * @return array
     */
    public function render()
    {
        if ($this->body instanceof MimeMultipart) {
            return $this->body->render();
        } else if ($this->body instanceof MessagePart) {
            return $this->body->render(false);
        }

        return  $this->_render($this->_wrap($this->body));
    }

    // This is hack how to force CakeEmail to always generate multipart message.
    protected function _renderTemplates($content)
    {
        $this->_boundary = md5(uniqid());
        $output = parent::_renderTemplates($content);
        $output[''] = '';
        return $output;
    }

    protected function _render($content)
    {
        if ($this->body instanceof MimeMultipart) {
            return $this->body->render();
        } else if ($this->body instanceof MessagePart) {
            return $this->body->render(false);
        }

        return parent::_render($content);
    }

    public function send($content = null)
    {
        if ($content !== null) {
            throw new InvalidArgumentException("Content must be null for CakeEmailExtended.");
        }
        return parent::send($this->body);
    }

    public function __toString()
    {
        return implode("\n", $this->render());
    }
}

class MimeMultipart
{
    /**
     * @var MessagePart[]
     */
    private $parts = array();

    /**
     * @var string
     */
    private $subtype;

    /**
     * @var string
     */
    private $boundary;

    /**
     * @var array
     */
    private $additionalTypes;

    /**
     * MimeMultipart constructor.
     * @param string $subtype
     * @param array $additionalTypes
     */
    public function __construct($subtype = 'mixed', $additionalTypes = array())
    {
        $this->subtype = $subtype;
        $this->boundary = md5(uniqid());
        $this->additionalTypes = $additionalTypes;
    }

    /**
     * @return string
     */
    public function getContentType()
    {
        $contentType = array_merge(array('multipart/' . $this->subtype), $this->additionalTypes);
        $contentType[] = 'boundary="' . $this->boundary . '"';
        return implode('; ', $contentType);
    }

    public function boundary()
    {
        return $this->boundary;
    }

    public function addPart(MessagePart $part)
    {
        $this->parts[] = $part;
    }

    /**
     * @return array
     */
    public function render()
    {
        $msg = array('--' . $this->boundary);
        foreach ($this->parts as $part) {
            $msg = array_merge($msg, $part->render());
            $msg[] = '--' . $this->boundary;
        }
        $msg[count($msg) - 1] .= '--'; // last boundary
        return $msg;
    }

    public function __toString()
    {
        return implode("\n", $this->render());
    }
}

class MessagePart
{
    /**
     * @var array
     */
    private $headers = array();

    /**
     * @var array
     */
    private $payload;

    /**
     * @param string $name
     * @param string|array $value
     */
    public function addHeader($name, $value)
    {
        if (is_array($value)) {
            $value = implode('; ', $value);
        }

        $this->headers[$name] = $value;
    }

    /**
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * @param array|string $payload
     */
    public function setPayload($payload)
    {
        if (is_string($payload)) {
            $payload = explode("\n", $payload);
        }

        $this->payload = $payload;
    }

    /**
     * @param bool $withHeaders
     * @return array
     */
    public function render($withHeaders = true)
    {
        $msg = array();
        if ($withHeaders) {
            foreach ($this->headers as $name => $value) {
                $msg[] = "$name: $value";
            }
            $msg[] = '';
        }
        return array_merge($msg, $this->payload);
    }

    public function __toString()
    {
        return implode("\n", $this->render());
    }
}

class SendEmail
{
    /**
     * @var Crypt_GPG
     */
    private $gpg;

    public function __construct($gpg = null)
    {
        $this->gpg = $gpg;
    }

    /**
     * @param array $params
     * @return array|bool
     * @throws SendEmailException
     */
    public function sendExternal(array $params)
    {
        foreach (array('body', 'reply-to', 'to', 'subject', 'text') as $requiredParam) {
            if (!isset($params[$requiredParam])) {
                throw new InvalidArgumentException("Param '$requiredParam' is required, but not provided.");
            }
        }

        $params['body'] = str_replace('\n', PHP_EOL, $params['body']); // TODO: Why this?

        $attachments = array();
        if (!empty($params['requestor_gpgkey'])) {
            $attachments['gpgkey.asc'] = array(
                'data' => $params['requestor_gpgkey']
            );
        }

        if (!empty($params['attachments'])) {
            foreach ($params['attachments'] as $key => $value) {
                $attachments[$key] = array('data' => $value);
            }
        }

        $email = new CakeEmailExtended();
        $email->replyTo($params['reply-to']);
        $email->from(Configure::read('MISP.email'));
        $email->returnPath(Configure::read('MISP.email'));
        $email->to($params['to']);
        $email->subject($params['subject']);
        $email->emailFormat('text');
        $email->body($params['body']);
        $email->attachments($attachments);

        $mock = false;
        if (!empty(Configure::read('MISP.disable_emailing')) || !empty($params['mock'])) {
            $email->transport('Debug');
            $mock = true;
        }

        if (!empty($params['gpgkey'])) {
            if (!$this->gpg) {
                throw new SendEmailException("GPG encryption is enabled, but GPG is not configured.");
            }
            
            try {
                $fingerprint = $this->importAndValidateGpgPublicKey($params['gpgkey']);
            } catch (Crypt_GPG_NoDataException $e) {
                throw new SendEmailException("The message could not be encrypted because the provided key is invalid.", 0, $e);
            }
            if (!$fingerprint) {
                throw new SendEmailException("The message could not be encrypted because the provided key is either expired or cannot be used for encryption.");
            }
            try {
                $this->gpg->addEncryptKey($fingerprint);
                $this->encryptByGpg($email);
            } catch (Exception $e) {
                throw new SendEmailException("The message could not be encrypted.", 0, $e);
            }
        }

        try {
            $result = $email->send();
        } catch (Exception $e) {
            throw new SendEmailException("The message could be sent.", 0, $e);
        }

        if ($result && !$mock) {
            return true;
        }
        return $result;
    }

    /**
     * @param array $user
     * @param string $subject
     * @param string $body
     * @param string|null $bodyWithoutEncryption
     * @param array $replyToUser
     * @return bool True if e-mail is encrypted, false if not.
     * @throws SendEmailException
     */
    public function sendToUser(array $user, $subject, $body, $bodyWithoutEncryption = null, array $replyToUser = array())
    {
        if (Configure::read('MISP.disable_emailing')) {
            throw new SendEmailException('Emailing is currently disabled on this instance.');
        }

        // check if the e-mail can be encrypted
        $canEncryptGpg = isset($user['User']['gpgkey']) && !empty($user['User']['gpgkey']);
        $canEncryptSmime = isset($user['User']['certif_public']) && !empty($user['User']['certif_public']) && Configure::read('SMIME.enabled');

        if (Configure::read('GnuPG.onlyencrypted') && !$canEncryptGpg && !$canEncryptSmime) {
            throw new SendEmailException('Encrypted messages are enforced and the message could not be encrypted for this user as no valid encryption key was found.');
        }

        // If bodyonlyencrypted is enabled and the user has no encryption key, use the alternate body (if it exists)
        if (Configure::read('GnuPG.bodyonlyencrypted') && !$canEncryptSmime && !$canEncryptGpg && $bodyWithoutEncryption) {
            $body = $bodyWithoutEncryption;
        }

        $body = str_replace('\n', PHP_EOL, $body); // TODO: Why this?

        $email = $this->create($user, $subject, $body, array(), $replyToUser);

        if (Configure::read('GnuPG.sign')) {
            if (!$this->gpg) {
                throw new SendEmailException("GPG signing is enabled, but GPG is not configured.");
            }

            try {
                $this->gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
                $this->signByGpg($email);
            } catch (Exception $e) {
                throw new SendEmailException("The message could not be signed.", 0, $e);
            }
        }

        $encrypted = false;

        if ($canEncryptGpg) {
            if (!$this->gpg) {
                throw new SendEmailException("GPG encryption is enabled, but GPG is not configured.");
            }
            
            try {
                $fingerprint = $this->importAndValidateGpgPublicKey($user['User']['gpgkey']);
            } catch (Crypt_GPG_NoDataException $e) {
                throw new SendEmailException("The message could not be encrypted because the provided key is invalid.", 0, $e);
            }

            if (!$fingerprint) {
                throw new SendEmailException("The message could not be encrypted because the provided key is either expired or cannot be used for encryption.");
            }

            try {
                $this->gpg->addEncryptKey($fingerprint);
                $this->encryptByGpg($email);
                $encrypted = true;
            } catch (Exception $e) {
                throw new SendEmailException("The message could not be encrypted.", 0, $e);
            }
        }

        if (!$canEncryptGpg && $canEncryptSmime) {
            $this->signBySmime($email);
            $this->encryptBySmime($email, $user['User']['certif_public']);
            $encrypted = true;
        }

        try {
            $email->send();
            return $encrypted;
        } catch (Exception $e) {
            throw new SendEmailException("The message could be sent.", 0, $e);
        }
    }

    /**
     * @param string $certificate
     * @return bool
     * @throws Exception
     */
    public function testSmimeCertificate($certificate)
    {
        try {
            // Try to encrypt empty message
            $this->encryptTextBySmime($certificate, '');
        } catch (SendEmailException $e) {
            throw new Exception("This certificate cannot be used to encrypt email", 0, $e);
        }

        $parsed = openssl_x509_parse($certificate);

        // 5 should be 'smimeencrypt'
        if (!($parsed['purposes'][5][0] === 1 && $parsed['purposes'][5][2] === 'smimeencrypt')) {
            throw new Exception('This certificate cannot be used to encrypt email');
        }

        $now = new DateTime("now");
        $validToTime = new DateTime("@{$parsed['validTo_time_t']}");
        if ($validToTime <= $now) {
            throw new Exception('This certificate is expired');
        }

        return true;
    }

    /**
     * @param array $user
     * @param string $subject
     * @param string $body
     * @param array $attachments
     * @param array $replyToUser
     * @return CakeEmailExtended
     */
    private function create(array $user, $subject, $body, array $attachments = array(), array $replyToUser = array())
    {
        $email = new CakeEmailExtended();

        // We must generate message ID by own, because CakeEmail returns different message ID for every call of
        // getHeaders() method.
        $email->messageId($this->generateMessageId($email));

        // If the e-mail is sent on behalf of a user, then we want the target user to be able to respond to the sender.
        // For this reason we should also attach the public key of the sender along with the message (if applicable).
        if ($replyToUser) {
            $email->replyTo($replyToUser['User']['email']);
            if (!empty($replyToUser['User']['gpgkey'])) {
                $attachments['gpgkey.asc'] = $replyToUser['User']['gpgkey'];
            } elseif (!empty($replyToUser['User']['certif_public'])) {
                $attachments[$replyToUser['User']['email'] . '.pem'] = $replyToUser['User']['certif_public'];
            }
        }

        $email->from(Configure::read('MISP.email'));
        $email->returnPath(Configure::read('MISP.email'));
        $email->to($user['User']['email']);
        $email->subject($subject);
        $email->emailFormat('text');
        $email->body($body);

        foreach ($attachments as $key => $value) {
            $attachments[$key] = array('data' => $value);
        }
        $email->attachments($attachments);

        return $email;
    }

    /**
     * @param CakeEmailExtended $email
     */
    private function signByGpg(CakeEmailExtended $email)
    {
        $renderedEmail = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', array(
            'multipart/mixed',
            'boundary="' . $email->boundary() . '"',
            'protected-headers="v1"',
        ));
        $originalHeaders = $email->getHeaders(array('subject', 'from', 'to'));
        $protectedHeaders = array('From', 'To', 'Message-ID', 'Subject');
        foreach ($protectedHeaders as $header) {
            if (isset($originalHeaders[$header])) {
                $messagePart->addHeader($header, $originalHeaders[$header]);
            }
        }
        $messagePart->setPayload($renderedEmail);

        // GPG message to sign must be delimited by <CR><LF>
        $messageToSign = implode("\r\n", $messagePart->render());
        $signature = $this->gpg->sign($messageToSign, Crypt_GPG::SIGN_MODE_DETACHED);
        $signatureInfo = $this->gpg->getLastSignatureInfo();

        $signaturePart = new MessagePart();
        $signaturePart->addHeader('Content-Type', array('application/pgp-signature', 'name="signature.asc"'));
        $signaturePart->addHeader('Content-Description', 'OpenPGP digital signature');
        $signaturePart->addHeader('Content-Disposition', array('attachment', 'filename="signature.asc"'));
        $signaturePart->setPayload($signature);

        $output = new MimeMultipart('signed', array(
            "micalg=pgp-{$signatureInfo->getHashAlgorithmName()}",
            'protocol="application/pgp-signature"'
        ));
        $output->addPart($messagePart);
        $output->addPart($signaturePart);

        $email->body($output);
    }

    /**
     * @param CakeEmailExtended $email
     */
    private function encryptByGpg(CakeEmailExtended $email)
    {
        $versionPart = new MessagePart();
        $versionPart->addHeader('Content-Type', 'application/pgp-encrypted');
        $versionPart->addHeader('Content-Description', 'PGP/MIME version identification');
        $versionPart->setPayload("Version 1\n");

        $rendered = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', $email->getHeaders()['Content-Type']);
        $messagePart->setPayload($rendered);
        $rendered = $messagePart->render();

        $messageToEncrypt = implode("\r\n", $rendered);
        $encrypted = $this->gpg->encrypt($messageToEncrypt, true);

        $encryptedPart = new MessagePart();
        $encryptedPart->addHeader('Content-Type', array('application/octet-stream', 'name="encrypted.asc"'));
        $encryptedPart->addHeader('Content-Description', 'OpenPGP encrypted message');
        $encryptedPart->addHeader('Content-Disposition', array('inline', 'filename="encrypted.asc"'));
        $encryptedPart->setPayload($encrypted);

        $output = new MimeMultipart('encrypted', array('protocol="application/pgp-encrypted"'));
        $output->addPart($versionPart);
        $output->addPart($encryptedPart);

        $email->body($output);
    }

    /**
     * @param CakeEmailExtended $email
     * @throws SendEmailException
     */
    private function signBySmime(CakeEmailExtended $email)
    {
        $renderedEmail = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', array(
            'multipart/mixed',
            'boundary="' . $email->boundary() . '"',
        ));
        $messagePart->setPayload($renderedEmail);

        $signaturePart = new MessagePart();
        $signaturePart->addHeader('Content-Type', array('application/pkcs7-signature', 'name="smime.p7s"'));
        $signaturePart->addHeader('Content-Transfer-Encoding', 'base64');
        $signaturePart->addHeader('Content-Disposition', array('attachment', 'filename="smime.p7s"'));
        $signaturePart->setPayload($this->signTextBySmime(implode("\r\n", $messagePart->render())));

        $output = new MimeMultipart('signed', array('protocol="application/x-pkcs7-signature"', 'micalg="sha-256"'));
        $output->addPart($messagePart);
        $output->addPart($signaturePart);

        $email->body($output);
    }

    /**
     * @param CakeEmailExtended $email
     * @param string $publicKey
     * @throws SendEmailException
     */
    private function encryptBySmime(CakeEmailExtended $email, $publicKey)
    {
        $rendered = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', $email->getHeaders()['Content-Type']);
        $messagePart->setPayload($rendered);
        $rendered = $messagePart->render();

        $encrypted = $this->encryptTextBySmime($publicKey, implode("\r\n", $rendered));

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Transfer-Encoding', 'base64');
        $messagePart->addHeader('Content-Type', 'application/pkcs7-mime; name="smime.p7m"; smime-type="enveloped-data"');
        $messagePart->addHeader('Content-Disposition', 'attachment; filename="smime.p7m"');
        $messagePart->addHeader('Content-Description', 'S/MIME Encrypted Message');
        $messagePart->setPayload($encrypted);

        $email->body($messagePart);
    }

    /**
     * @param string $body
     * @return false|string
     * @throws SendEmailException
     */
    private function signTextBySmime($body)
    {
        $certPublicSignPath = Configure::read('SMIME.cert_public_sign');
        $keySignPath = Configure::read('SMIME.key_sign');
        if (empty($certPublicSignPath)) {
            throw new SendEmailException("Configuration value 'SMIME.cert_public_sign' is not defined.");
        }
        if (empty($keySignPath)) {
            throw new SendEmailException("Configuration value 'SMIME.key_sign' is not defined.");
        }
        if (!is_readable($certPublicSignPath)) {
            throw new SendEmailException("Certification file '$certPublicSignPath' is not readable.");
        }
        if (!is_readable($keySignPath)) {
            throw new SendEmailException("Sign key file '$keySignPath' is not readable.");
        }
        $certPublicSign = openssl_x509_read(file_get_contents($certPublicSignPath));
        if (!$certPublicSign) {
            throw new SendEmailException("Certification file '$certPublicSignPath' is not valid X.509 file: " . openssl_error_string());
        }
        $keySign = openssl_pkey_get_private(file_get_contents($keySignPath), Configure::read('SMIME.password'));
        if (!$keySign) {
            throw new SendEmailException("Sign key file '$keySignPath' is not valid private key file: " . openssl_error_string());
        }

        list($inputFile, $outputFile) = $this->createInputOutputFiles($body);
        $result = openssl_pkcs7_sign($inputFile->pwd(), $outputFile->pwd(), $certPublicSign, $keySign, array(), 0);
        $inputFile->delete();

        if ($result) {
            $data = $outputFile->read();
            $outputFile->delete();
            $parts = explode("\n\n", $data);
            return $parts[1] . "\n";

        } else {
            $outputFile->delete();
            throw new SendEmailException('Failed while attempting to sign the S/MIME message: ' . openssl_error_string());
        }
    }

    /**
     * @param string $publicKey
     * @param string $body
     * @return string
     * @throws SendEmailException
     */
    private function encryptTextBySmime($publicKey, $body)
    {
        $publicKey = openssl_x509_read($publicKey);
        if (!$publicKey) {
            throw new SendEmailException("Certification file is not valid X.509 file: " . openssl_error_string());
        }

        list($inputFile, $outputFile) = $this->createInputOutputFiles($body);
        $result = openssl_pkcs7_encrypt($inputFile->pwd(), $outputFile->pwd(), $publicKey, array(), 0, OPENSSL_CIPHER_AES_256_CBC);
        $inputFile->delete();

        if ($result) {
            $encryptedBody = $outputFile->read();
            $outputFile->delete();
            $parts = explode("\n\n", $encryptedBody);
            return $parts[1];
        } else {
            $outputFile->delete();
            throw new SendEmailException('Could not encrypt the S/MIME message: ' . openssl_error_string());
        }
    }

    /**
     * @param string $content
     * @return File[]
     * @throws SendEmailException
     */
    private function createInputOutputFiles($content)
    {
        $dir = APP . 'tmp' . DS . 'SMIME';
        if (!file_exists($dir)) {
            if (!mkdir($dir, 0750, true)) {
                throw new SendEmailException("The SMIME temp directory '$dir' is not writeable.");
            }
        }

        App::uses('FileAccessTool', 'Tools');
        $fileAccessTool = new FileAccessTool();
        $inputFile = $fileAccessTool->createTempFile($dir, 'SMIME');
        $fileAccessTool->writeToFile($inputFile, $content);

        $outputFile = $fileAccessTool->createTempFile($dir, 'SMIME');
        return array(new File($inputFile), new File($outputFile));
    }

    /**
     * Check if public key is not expired and can encrypt.
     * @param string $gpgKey
     * @return string|bool Fingerprint if key is valid, false otherwise.
     */
    private function importAndValidateGpgPublicKey($gpgKey)
    {
        $keyImportOutput = $this->gpg->importKey($gpgKey);
        $key = $this->gpg->getKeys($keyImportOutput['fingerprint']);
        $subKeys = $key[0]->getSubKeys();
        $currentTimestamp = time();

        foreach ($subKeys as $subKey) {
            $expiration = $subKey->getExpirationDate();
            if (($expiration == 0 || $currentTimestamp < $expiration) && $subKey->canEncrypt()) {
                // key is valid, return fingerprint
                return $keyImportOutput['fingerprint'];
            }
        }

        return false;
    }

    /**
     * This method generates Message-ID (RFC 2392) according to recommendation from https://www.jwz.org/doc/mid.html.
     * CakePHP by default uses CakeText::uuid() method for first part, but UUID leaks machine IP address.
     *
     * @param CakeEmail $email
     * @return string
     */
    private function generateMessageId(CakeEmail $email)
    {
        list($microseconds, $seconds) = explode(" ", microtime());
        $microseconds = intval((float) $microseconds * 1000000);
        $first = base_convert($seconds, 10, 36) . base_convert($microseconds, 10, 36);
        $second = base_convert(mt_rand(), 10, 36) . base_convert(mt_rand(), 10, 36);
        return "<$first.$second@{$email->domain()}>";
    }
}
