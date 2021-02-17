<?php
App::uses('CakeEmail', 'Network/Email');

class SendEmailException extends Exception {}

/**
 * Class CakeEmailExtended
 *
 * Extends `CakeEmail` to implement RFC 4880 and 3156.
 *
 * @see https://dkg.fifthhorseman.net/notes/inline-pgp-harmful/
 * @see https://www.dalesandro.net/create-self-signed-smime-certificates/
 */
class CakeEmailExtended extends CakeEmail
{
    /**
     * @var MimeMultipart|MessagePart
     */
    private $body;

    /**
     * @param array $include
     * @return array
     */
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

    /**
     * @return string|null
     */
   public function boundary()
   {
       if ($this->body instanceof MimeMultipart) {
           return $this->body->boundary();
       }

       return $this->_boundary;
   }

    /**
     * @param string|null|MimeMultipart|MessagePart $message
     * @return string|null|MimeMultipart|MessagePart|CakeEmailExtended
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
     * @var CryptGpgExtended
     */
    private $gpg;

    /**
     * @param CryptGpgExtended|null $gpg
     */
    public function __construct(CryptGpgExtended $gpg = null)
    {
        if ($gpg) {
            $gpg->clearDecryptKeys()
                ->clearEncryptKeys()
                ->clearSignKeys()
                ->clearPassphrases();
            $this->gpg = $gpg;
        }
    }

    /**
     * @param array $params
     * @return array|bool
     * @throws Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendExternal(array $params)
    {
        foreach (array('body', 'reply-to', 'to', 'subject') as $requiredParam) {
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
            throw new SendEmailException("The message could not be sent.", 0, $e);
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
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendToUser(array $user, $subject, $body, $bodyWithoutEncryption = null, array $replyToUser = array())
    {
        if (Configure::read('MISP.disable_emailing')) {
            throw new SendEmailException('Emailing is currently disabled on this instance.');
        }

        if (!isset($user['User'])) {
            throw new InvalidArgumentException("Invalid user model provided.");
        }

        // Check if the e-mail can be encrypted
        $canEncryptGpg = isset($user['User']['gpgkey']) && !empty($user['User']['gpgkey']);
        $canEncryptSmime = isset($user['User']['certif_public']) && !empty($user['User']['certif_public']) && Configure::read('SMIME.enabled');

        if (Configure::read('GnuPG.onlyencrypted') && !$canEncryptGpg && !$canEncryptSmime) {
            throw new SendEmailException('Encrypted messages are enforced and the message could not be encrypted for this user as no valid encryption key was found.');
        }

        // If 'bodyonlyencrypted' is enabled and the user has no encryption key, use the alternate body (if it exists)
        if (Configure::read('GnuPG.bodyonlyencrypted') && !$canEncryptSmime && !$canEncryptGpg && $bodyWithoutEncryption) {
            $body = $bodyWithoutEncryption;
        }

        $body = str_replace('\n', PHP_EOL, $body); // TODO: Why this?

        $email = $this->create($user, $subject, $body, array(), $replyToUser);

        $signed = false;
        if (Configure::read('GnuPG.sign')) {
            if (!$this->gpg) {
                throw new SendEmailException("GPG signing is enabled, but GPG is not initialized. Check debug log why GPG could not be initialized.");
            }

            try {
                $gnupgEmail = Configure::read('GnuPG.email');
                if (empty($gnupgEmail)) {
                    throw new Exception("GPG email signing is enabled but variable 'GnuPG.email' is not set.");
                }

                $this->gpg->addSignKey($gnupgEmail, Configure::read('GnuPG.password'));
                $this->signByGpg($email, $replyToUser);
                $email->addHeaders(array('Autocrypt' => $this->generateAutocrypt($gnupgEmail)));
                $this->gpg->clearSignKeys();

                $signed = true;
            } catch (Exception $e) {
                throw new SendEmailException("The message could not be signed by GPG.", 0, $e);
            }
        }

        $encrypted = false;
        if ($canEncryptGpg) {
            if (!$this->gpg) {
                throw new SendEmailException("GPG signing is enabled, but GPG is not initialized. Check debug log why GPG could not be initialized.");
            }

            try {
                $fingerprint = $this->importAndValidateGpgPublicKey($user['User']['gpgkey']);
            } catch (Crypt_GPG_NoDataException $e) {
                throw new SendEmailException("The message could not be encrypted because the provided GPG key is invalid.", 0, $e);
            }

            if (!$fingerprint) {
                throw new SendEmailException("The message could not be encrypted because the provided GPG key is either expired or cannot be used for encryption.");
            }

            try {
                $this->gpg->addEncryptKey($fingerprint);
                $this->encryptByGpg($email);
                $this->gpg->clearEncryptKeys();

                if ($signed && Configure::read('GnuPG.obscure_subject')) {
                    // If message is signed, we can remove subject from unencrypted part of email and replace with '...',
                    // because subject is also part of signed data. Three dots are used according to
                    // 'draft-autocrypt-lamps-protected-headers-01' standard. This behaviour must be enabled by
                    // 'GnuPG.obscure_subject' setting.
                    $email->subject('...');
                }

                $encrypted = true;
            } catch (Exception $e) {
                throw new SendEmailException('The message could not be encrypted by GPG.', 0, $e);
            }
        }

        if (!$canEncryptGpg && $canEncryptSmime) {
            if (!empty(Configure::read('SMIME.cert_public_sign')) && !empty(Configure::read('SMIME.key_sign'))) {
                $this->signBySmime($email);
            }
            $this->encryptBySmime($email, $user['User']['certif_public']);
            $encrypted = true;
        }

        try {
            $email->send();
            return $encrypted;
        } catch (Exception $e) {
            throw new SendEmailException('The message could not be sent.', 0, $e);
        }
    }

    /**
     * Test if S/MIME certificate is valid for email encrypting.
     *
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
            throw new Exception('This S/MIME certificate cannot be used to encrypt email.', 0, $e);
        }

        $parsed = openssl_x509_parse($certificate);

        if (!$parsed) {
            throw new Exception('Could not parse S/MIME certificate');
        }

        if ($parsed['purposes'][X509_PURPOSE_SMIME_ENCRYPT][0] !== true) {
            throw new Exception('This S/MIME certificate cannot be used to encrypt email.');
        }

        $now = new DateTime();
        $validToTime = new DateTime("@{$parsed['validTo_time_t']}");
        if ($validToTime <= $now) {
            throw new Exception('This S/MIME certificate expired at ' . $validToTime->format('c'));
        }

        return true;
    }

    /**
     * @param array $user User model
     * @param string $subject
     * @param string $body
     * @param array $attachments
     * @param array $replyToUser User model
     * @return CakeEmailExtended
     */
    private function create(array $user, $subject, $body, array $attachments = array(), array $replyToUser = array())
    {
        $email = new CakeEmailExtended();

        // We must generate message ID by own, because CakeEmail returns different message ID for every call of
        // getHeaders() method.
        $email->messageId($this->generateMessageId($email));
        // The same problem is with 'Date' header, that we need to protect by GPG signature.
        $email->addHeaders(array('Date' => date(DATE_RFC2822)));

        // If the e-mail is sent on behalf of a user, then we want the target user to be able to respond to the sender.
        // For this reason we should also attach the public key of the sender along with the message (if applicable).
        if ($replyToUser) {
            if (!isset($replyToUser['User']['email'])) {
                throw new InvalidArgumentException("Invalid replyToUser model provided.");
            }
            $email->replyTo($replyToUser['User']['email']);
            if (!empty($replyToUser['User']['gpgkey'])) {
                $attachments['gpgkey.asc'] = $replyToUser['User']['gpgkey'];
            } elseif (!empty($replyToUser['User']['certif_public'])) {
                $attachments[$replyToUser['User']['email'] . '.pem'] = $replyToUser['User']['certif_public'];
            }
        } else if (Configure::read('MISP.email_reply_to')) {
            $email->replyTo(Configure::read('MISP.email_reply_to'));
        }

        $email->from(Configure::read('MISP.email'));
        $email->returnPath(Configure::read('MISP.email')); // TODO?
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
     * @param array $replyToUser
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_KeyNotFoundException
     */
    private function signByGpg(CakeEmailExtended $email, array $replyToUser = array())
    {
        $renderedEmail = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', array(
            'multipart/mixed',
            'boundary="' . $email->boundary() . '"',
            'protected-headers="v1"',
        ));

        // Protect User-Facing Headers according to https://tools.ietf.org/id/draft-autocrypt-lamps-protected-headers-01.html
        $originalHeaders = $email->getHeaders(array('subject', 'from', 'to'));
        $protectedHeaders = array('From', 'To', 'Date', 'Message-ID', 'Subject', 'Reply-To');
        foreach ($protectedHeaders as $header) {
            if (isset($originalHeaders[$header])) {
                $messagePart->addHeader($header, $originalHeaders[$header]);
            }
        }

        // If the e-mail is sent on behalf of a user and that user has assigned GPG key, we will send his public key
        // in signed autocrypt header.
        if ($replyToUser) {
            if (!empty($replyToUser['User']['gpgkey'])) {
                $autocrypt = $this->generateAutocrypt($replyToUser['User']['email'], $replyToUser['User']['gpgkey'], false);
                $messagePart->addHeader('Autocrypt-Gossip', $autocrypt);
            }
        } else if (Configure::read('MISP.email_reply_to')) {
            $autocrypt = $this->generateAutocrypt(Configure::read('MISP.email_reply_to'), null, false);
            if ($autocrypt) {
                $messagePart->addHeader('Autocrypt-Gossip', $autocrypt);
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
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_KeyNotFoundException
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
        $result = openssl_pkcs7_sign($inputFile->pwd(), $outputFile->pwd(), $certPublicSign, $keySign, array(), PKCS7_DETACHED);
        $inputFile->delete();

        if ($result) {
            $data = $outputFile->read();
            $outputFile->delete();
            $parts = explode("\n\n", $data);
            return $parts[4] . "\n";

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
            throw new SendEmailException('Certification file is not valid X.509 file: ' . openssl_error_string());
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
     * @throws MethodNotAllowedException
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
     *
     * @param string $gpgKey
     * @return string|bool Fingerprint if key is valid, false otherwise.
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     * @throws Crypt_GPG_NoDataException
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
     * This method generates Message-ID (RFC 2392).
     *
     * @param CakeEmail $email
     * @return string
     */
    private function generateMessageId(CakeEmail $email)
    {
        $uuid = str_replace('-', '', CakeText::uuid());
        return "<$uuid@{$email->domain()}>";
    }

    /**
     * Generates Autocrypt header.
     *
     * If $gpgKey is not provided, GPG will try to find correct key by given e-mail address. If no key found, `null` is
     * returned.
     *
     * @see https://autocrypt.org/level1.html
     * @param string $address
     * @param string|null $gpgKey
     * @param bool $preferEncrypt
     * @return string|null
     * @throws Crypt_GPG_Exception
     */
    private function generateAutocrypt($address, $gpgKey = null, $preferEncrypt = true)
    {
        if ($gpgKey) {
            $keyImportOutput = $this->gpg->importKey($gpgKey);
            $keyData = $this->gpg->exportPublicKeyMinimal($keyImportOutput['fingerprint'], false);
        } else {
            try {
                $keyData = $this->gpg->exportPublicKeyMinimal($address, false);
            } catch (Crypt_GPG_KeyNotFoundException $e) {
                return null;
            }
        }

        $parts = array("addr=$address");
        if ($preferEncrypt) {
            $parts[] = 'prefer-encrypt=mutual';
        }
        $parts[] = 'keydata=' . base64_encode($keyData);
        return implode('; ', $parts);
    }
}
