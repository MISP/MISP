<?php

namespace App\Lib\Tools;

use Cake\Core\Configure;
use Cake\I18n\FrozenTime;
use Cake\Mailer\Mailer as CakeEmail;
use Cake\Utility\Text;
use Exception;
use InvalidArgumentException;

class SendEmailException extends Exception
{
}

class CakeEmailBody
{
    /** @var string|null */
    public $html;

    /** @var string|null */
    public $text;

    /** @var string|null */
    protected $_boundary;

    public function __construct($text = null, $html = null)
    {
        $this->html = $html;
        $this->text = $text;
    }

    /**
     * @return string
     */
    public function format()
    {
        if (!empty($this->html) && !empty($this->text)) {
            return 'both';
        }

        if (!empty($this->html)) {
            return 'html';
        }
        return 'text';
    }

    public function toArray()
    {
        $email = [];

        if ($this->html) {
            $email['html'] = $this->html;
        }
        if ($this->text) {
            $email['text'] = $this->text;
        }

        return $email;
    }
}

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
     * @var MimeMultipart|MessagePart|CakeEmailBody
     */
    private $body;

    /** @var string|null */
    protected $_boundary;

    /**
     * @param array $include
     * @return array
     */
    public function getHeaders($include = [])
    {
        $headers = parent::getHeaders($include);

        if ($this->body instanceof MimeMultipart) {
            $headers['Content-Type'] = $this->body->getContentType();
        } else if ($this->body instanceof MessagePart) {
            $headers = array_merge($headers, $this->body->getHeaders());
        } else if ($this->getEmailFormat() !== 'both') { // generate correct content-type header for 'text' or 'html' format
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
    public function setBody($message = null)
    {
        if ($message === null) {
            return $this->body;
        }
        $this->body = $message;
        return $this;
    }

    /**
     * @return Message
     */
    public function render(string $content = '')
    {
        if ($this->body instanceof MimeMultipart) {
            return $this->message->setBody(['text' => $this->body->__toString()]);
        } else if ($this->body instanceof MessagePart) {
            return $this->message->setBody($this->body->render(false));
        } else if ($this->body instanceof CakeEmailBody) {
            return $this->message->setBody($this->body->toArray()); // @see _renderTemplates
        }

        throw new InvalidArgumentException("Expected that body is instance of MimeMultipart, MessagePart or CakeEmailBody, " . gettype($this->body) . " given.");
    }

    protected function _renderTemplates($content)
    {
        if (!$this->body instanceof CakeEmailBody) {
            throw new InvalidArgumentException("Expected instance of CakeEmailBody, " . gettype($this->body) . " given.");
        }

        $this->_boundary = md5(mt_rand());

        $rendered = [];
        if (!empty($this->body->text)) {
            $rendered['text'] = $this->body->text;
        }
        if (!empty($this->body->html)) {
            $rendered['html'] = $this->body->html;
        }

        foreach ($rendered as $type => $content) {
            $content = str_replace(["\r\n", "\r"], "\n", $content);
            $content = $this->_encodeString($content, $this->getCharset());
            $content = $this->_wrap($content);
            $content = implode("\n", $content);
            $rendered[$type] = rtrim($content, "\n");
        }

        // This is hack how to force CakeEmail to always generate multipart message.
        $rendered[''] = '';
        return $rendered;
    }

    protected function _render($content)
    {
        if ($this->body instanceof MimeMultipart) {
            return $this->body->render();
        } else if ($this->body instanceof MessagePart) {
            return $this->body->render(false);
        }

        return parent::render($content);
    }

    public function send(?string $action = null, array $args = [], array $headers = []): array
    {
        return parent::send($action, $args, $headers);
    }

    public function __toString()
    {
        return implode("\n", $this->render()->getBody());
    }
}

class MimeMultipart
{
    /**
     * @var MessagePart[]
     */
    private $parts = [];

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
    public function __construct($subtype = 'mixed', $additionalTypes = [])
    {
        $this->subtype = $subtype;
        $this->boundary = md5(mt_rand());
        $this->additionalTypes = $additionalTypes;
    }

    /**
     * @return string
     */
    public function getContentType()
    {
        $contentType = array_merge(['multipart/' . $this->subtype], $this->additionalTypes);
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
        $msg = ['--' . $this->boundary];
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
    private $headers = [];

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
        $msg = [];
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
    /** @var CryptGpgExtended */
    private $gpg;

    /** @var string|null */
    private $transport;

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
     * @param string $transport
     */
    public function setTransport($transport)
    {
        $this->transport = $transport;
    }

    /**
     * @param array $params
     * @return array|bool
     * @throws \Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendExternal(array $params)
    {
        foreach (['body', 'reply-to', 'to', 'subject'] as $requiredParam) {
            if (!isset($params[$requiredParam])) {
                throw new InvalidArgumentException("Param '$requiredParam' is required, but not provided.");
            }
        }

        $body = str_replace('\n', PHP_EOL, $params['body']); // TODO: Why this?
        $body = new CakeEmailBody($body);

        $attachments = [];
        if (!empty($params['requestor_gpgkey'])) {
            $attachments['gpgkey.asc'] = [
                'data' => $params['requestor_gpgkey']
            ];
        }

        if (!empty($params['attachments'])) {
            foreach ($params['attachments'] as $key => $value) {
                $attachments[$key] = ['data' => $value];
            }
        }

        $email = new CakeEmailExtended();
        $email->setReplyTo($params['reply-to']);
        $email->setFrom(Configure::read('MISP.email'));
        $email->setReturnPath(Configure::read('MISP.email'));
        $email->setTo($params['to']);
        $email->setSubject($params['subject']);
        $email->setEmailFormat($body->format());
        $email->setBody($body);
        $email->attachments($attachments);

        if ($this->transport) {
            $email->transport($this->transport);
        }

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
            } catch (\Crypt_GPG_Exception $e) {
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
     * @param SendEmailTemplate|string $body
     * @param string|false $bodyWithoutEncryption
     * @param array $replyToUser
     * @return array
     * @throws \Crypt_GPG_BadPassphraseException
     * @throws \Crypt_GPG_Exception
     * @throws SendEmailException
     */
    public function sendToUser(array $user, $subject, $body, $bodyWithoutEncryption = false, array $replyToUser = [])
    {
        if ($body instanceof SendEmailTemplate && $bodyWithoutEncryption !== false) {
            throw new InvalidArgumentException("When body is instance of SendEmailTemplate, \$bodyWithoutEncryption must be false.");
        }

        if (Configure::read('MISP.disable_emailing')) {
            throw new SendEmailException('Emailing is currently disabled on this instance.');
        }

        if (!isset($user)) {
            throw new InvalidArgumentException("Invalid user model provided.");
        }

        // Intentional `array_key_exists` instead of `isset`
        if (!array_key_exists('gpgkey', $user) || !array_key_exists('certif_public', $user)) {
            throw new InvalidArgumentException("User without `gpgkey` or `certif_public` field provided.");
        }

        // Check if the e-mail can be encrypted
        $canEncryptGpg = !empty($user['gpgkey']);
        $canEncryptSmime = !empty($user['certif_public']) && Configure::read('SMIME.enabled');

        if (Configure::read('GnuPG.onlyencrypted') && !$canEncryptGpg && !$canEncryptSmime) {
            throw new SendEmailException('Encrypted messages are enforced and the message could not be encrypted for this user as no valid encryption key was found.');
        }

        // If 'GnuPG.bodyonlyencrypted' is enabled and the user has no encryption key, use the alternate body
        $hideDetails = Configure::read('GnuPG.bodyonlyencrypted') && !$canEncryptSmime && !$canEncryptGpg;

        if ($body instanceof SendEmailTemplate) {
            $body->set('canEncryptSmime', $canEncryptSmime);
            $body->set('canEncryptGpg', $canEncryptGpg);
            $bodyContent = $body->render($hideDetails);
            $subject = $body->subject() ?: $subject; // Get generated subject from template
        } else {
            if ($hideDetails && $bodyWithoutEncryption) {
                $body = $bodyWithoutEncryption;
            }
            $bodyContent = new CakeEmailBody($body);
        }

        $email = $this->create($user, $subject, $bodyContent, [], $replyToUser);

        if ($this->transport) {
            $email->transport($this->transport);
        }

        // Generate `In-Reply-To` and `References` headers to group emails
        if ($body instanceof SendEmailTemplate && $body->referenceId()) {
            $reference = sha1($body->referenceId() . '|' .  Configure::read('MISP.uuid'));
            $reference = "<$reference@{$email->getDomain()}>";
            $email->addHeaders(
                [
                    'In-Reply-To' => $reference,
                    'References' => $reference,
                ]
            );
        }

        if ($body instanceof SendEmailTemplate && $body->listUnsubscribe()) {
            $email->addHeaders(['List-Unsubscribe' => "<{$body->listUnsubscribe()}>"]);
        }

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
                $email->addHeaders(['Autocrypt' => $this->generateAutocrypt($gnupgEmail)]);
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
                $fingerprint = $this->importAndValidateGpgPublicKey($user['gpgkey']);
            } catch (\Crypt_GPG_Exception $e) {
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
            $this->encryptBySmime($email, $user['certif_public']);
            $encrypted = true;
        }

        try {
            return [
                'contents' => $email->send(),
                'encrypted' => $encrypted,
                'subject' => $subject,
            ];
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

        $now = new FrozenTime();
        $validToTime = new FrozenTime("@{$parsed['validTo_time_t']}");
        if ($validToTime <= $now) {
            throw new Exception('This S/MIME certificate expired at ' . $validToTime->format('c'));
        }

        return true;
    }

    /**
     * @param array $user User model
     * @param string $subject
     * @param CakeEmailBody $body
     * @param array $attachments
     * @param array $replyToUser User model
     * @return CakeEmailExtended
     */
    private function create(array $user, $subject, CakeEmailBody $body, array $attachments = [], array $replyToUser = [])
    {
        $email = new CakeEmailExtended();

        $fromEmail = Configure::read('MISP.email');

        // Set correct domain when sending email from CLI
        $fromEmailParts = explode('@', $fromEmail, 2);
        if (isset($fromEmailParts[1])) {
            $email->setDomain($fromEmailParts[1]);
        }

        // We must generate message ID by own, because CakeEmail returns different message ID for every call of
        // getHeaders() method.
        $email->setMessageId($this->generateMessageId($email));
        // The same problem is with 'Date' header, that we need to protect by GPG signature.
        $email->addHeaders(['Date' => date(DATE_RFC2822)]);

        // If the e-mail is sent on behalf of a user, then we want the target user to be able to respond to the sender.
        // For this reason we should also attach the public key of the sender along with the message (if applicable).
        if ($replyToUser) {
            if (!isset($replyToUser['email'])) {
                throw new InvalidArgumentException("Invalid replyToUser model provided.");
            }
            $email->replyTo($replyToUser['email']);
            if (!empty($replyToUser['gpgkey'])) {
                $attachments['gpgkey.asc'] = $replyToUser['gpgkey'];
            } elseif (!empty($replyToUser['certif_public'])) {
                $attachments[$replyToUser['email'] . '.pem'] = $replyToUser['certif_public'];
            }
        } else if (Configure::read('MISP.email_reply_to')) {
            $email->replyTo(Configure::read('MISP.email_reply_to'));
        }

        $email->setFrom($fromEmail, Configure::read('MISP.email_from_name'));
        $email->setReturnPath($fromEmail); // TODO?
        $email->setTo($user['email']);
        $email->setSubject($subject);
        $email->setEmailFormat($body->format());
        $email->setBody($body);

        foreach ($attachments as $key => $value) {
            $attachments[$key] = ['data' => $value];
        }
        $email->setAttachments($attachments);

        return $email;
    }

    /**
     * @param CakeEmailExtended $email
     * @param array $replyToUser
     * @throws \Crypt_GPG_BadPassphraseException
     * @throws \Crypt_GPG_Exception
     * @throws \Crypt_GPG_KeyNotFoundException
     */
    private function signByGpg(CakeEmailExtended $email, array $replyToUser = [])
    {
        $renderedEmail = $email->render()->getBodyString();

        $messagePart = new MessagePart();
        $messagePart->addHeader(
            'Content-Type',
            [
                $email->getMessage()->getEmailFormat() === 'both' ? 'multipart/alternative' : 'multipart/mixed',
                'boundary="' . $email->boundary() . '"',
                'protected-headers="v1"',
            ]
        );

        // Protect User-Facing Headers and Structural Headers according to
        // https://tools.ietf.org/id/draft-autocrypt-lamps-protected-headers-02.html
        $originalHeaders = $email->getHeaders(['subject', 'from', 'to']);
        $protectedHeaders = ['From', 'To', 'Date', 'Message-ID', 'Subject', 'Reply-To', 'In-Reply-To', 'References'];
        foreach ($protectedHeaders as $header) {
            if (isset($originalHeaders[$header])) {
                $messagePart->addHeader($header, $originalHeaders[$header]);
            }
        }

        // If the e-mail is sent on behalf of a user and that user has assigned GPG key, we will send his public key
        // in signed autocrypt header.
        if ($replyToUser) {
            if (!empty($replyToUser['gpgkey'])) {
                $autocrypt = $this->generateAutocrypt($replyToUser['email'], $replyToUser['gpgkey'], false);
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
        $signature = $this->gpg->sign($messageToSign, \Crypt_GPG::SIGN_MODE_DETACHED);
        # write to file
        $signatureInfo = $this->gpg->getLastSignatureInfo();

        $signaturePart = new MessagePart();
        $signaturePart->addHeader('Content-Type', ['application/pgp-signature', 'name="signature.asc"']);
        $signaturePart->addHeader('Content-Description', 'OpenPGP digital signature');
        $signaturePart->addHeader('Content-Disposition', ['attachment', 'filename="signature.asc"']);
        $signaturePart->setPayload($signature);

        $output = new MimeMultipart(
            'signed',
            [
                "micalg=pgp-{$signatureInfo->getHashAlgorithmName()}",
                'protocol="application/pgp-signature"'
            ]
        );
        $output->addPart($messagePart);
        $output->addPart($signaturePart);

        $email->setBody($output);
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

        $rendered = $email->getBodyString();

        $messagePart = new MessagePart();
        $messagePart->addHeader('Content-Type', $email->getHeaders()['Content-Type']);
        $messagePart->setPayload($rendered);
        $rendered = $messagePart->render();

        $messageToEncrypt = implode("\r\n", $rendered);
        $encrypted = $this->gpg->encrypt($messageToEncrypt, true);

        $encryptedPart = new MessagePart();
        $encryptedPart->addHeader('Content-Type', ['application/octet-stream', 'name="encrypted.asc"']);
        $encryptedPart->addHeader('Content-Description', 'OpenPGP encrypted message');
        $encryptedPart->addHeader('Content-Disposition', ['inline', 'filename="encrypted.asc"']);
        $encryptedPart->setPayload($encrypted);

        $output = new MimeMultipart('encrypted', ['protocol="application/pgp-encrypted"']);
        $output->addPart($versionPart);
        $output->addPart($encryptedPart);

        $email->setBody($output);
    }

    /**
     * @param CakeEmailExtended $email
     * @throws SendEmailException
     */
    private function signBySmime(CakeEmailExtended $email)
    {
        $renderedEmail = $email->render();

        $messagePart = new MessagePart();
        $messagePart->addHeader(
            'Content-Type',
            [
                $email->getEmailFormat() === 'both' ? 'multipart/alternative' : 'multipart/mixed',
                'boundary="' . $email->boundary() . '"',
            ]
        );
        $messagePart->setPayload($renderedEmail);

        $signaturePart = new MessagePart();
        $signaturePart->addHeader('Content-Type', ['application/pkcs7-signature', 'name="smime.p7s"']);
        $signaturePart->addHeader('Content-Transfer-Encoding', 'base64');
        $signaturePart->addHeader('Content-Disposition', ['attachment', 'filename="smime.p7s"']);
        $signaturePart->setPayload($this->signTextBySmime(implode("\r\n", $messagePart->render())));

        $output = new MimeMultipart('signed', ['protocol="application/x-pkcs7-signature"', 'micalg="sha-256"']);
        $output->addPart($messagePart);
        $output->addPart($signaturePart);

        $email->setBody($output);
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

        $email->setBody($messagePart);
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
        $result = openssl_pkcs7_sign($inputFile->pwd(), $outputFile->pwd(), $certPublicSign, $keySign, [], PKCS7_DETACHED);
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
        $result = openssl_pkcs7_encrypt($inputFile->pwd(), $outputFile->pwd(), $publicKey, [], 0, OPENSSL_CIPHER_AES_256_CBC);
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
     * @throws Exception
     */
    private function createInputOutputFiles($content)
    {
        $dir = APP . 'tmp' . DS . 'SMIME';
        if (!file_exists($dir)) {
            if (!mkdir($dir, 0750, true)) {
                throw new SendEmailException("The SMIME temp directory '$dir' is not writeable.");
            }
        }

        $inputFile = FileAccessTool::createTempFile($dir, 'SMIME');
        FileAccessTool::writeToFile($inputFile, $content);

        $outputFile = FileAccessTool::createTempFile($dir, 'SMIME');
        return [new \SplFileObject($inputFile), new \SplFileObject($outputFile)];
    }

    /**
     * Check if public key is not expired and can encrypt.
     *
     * @param string $gpgKey
     * @return string|bool Fingerprint if key is valid, false otherwise.
     * @throws Crypt_GPG_BadPassphraseException
     * @throws Crypt_GPG_Exception
     * @throws \Crypt_GPG_Exception
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
        $uuid = str_replace('-', '', Text::uuid());
        return "<$uuid@{$email->getDomain()}>";
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
            } catch (\Crypt_GPG_KeyNotFoundException $e) {
                return null;
            }
        }

        $parts = ["addr=$address"];
        if ($preferEncrypt) {
            $parts[] = 'prefer-encrypt=mutual';
        }
        $parts[] = 'keydata=' . base64_encode($keyData);
        // Use the PHP wordwrap function to wrap the Autocrypt header to 74 (+ CRLF) to meet RFC 5322 - 2.1.1 line length limits 
        return wordwrap(implode('; ', $parts), 74, "\r\n\t", true);
    }
}
