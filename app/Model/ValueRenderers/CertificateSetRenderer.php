<?php

/**
 * Which certificates have been served from an address, and when they
 * were valid.
 *
 * The `x509` template is the widest one this page draws from — around
 * sixty relations — and almost all of them are about the key rather
 * than about the host. What a reader wants from a set of certificates
 * is the validity windows and the subjects: a certificate issued last
 * week on an address that has been quiet for a year is the finding.
 *
 * **The validity window is the ordering key and not the answer's
 * age.** A certificate object carries no observation date, so a set
 * sorted by when the module ran would put a decade-old certificate
 * above one issued yesterday whenever the older answer was fetched
 * second.
 */
class CertificateSetRenderer extends ValueRendererBase
{
    public $id = 'certificate-set';

    public $templates = array('x509');

    public $compact = 'Values/Renderers/certificate_set_compact';

    public $full = 'Values/Renderers/certificate_set_full';

    public $eventUse = self::EVENT_SET;

    const SUBJECT = array('subject-common-name', 'subject');

    const ISSUER = array('issuer-common-name', 'issuer');

    const FINGERPRINT = array(
        'x509-fingerprint-sha256',
        'x509-fingerprint-sha1',
        'x509-fingerprint-md5',
        'serial-number',
    );

    public function __construct()
    {
        $this->description = __('The certificates served from an'
            . ' address, and their validity windows.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->certificateOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $certificates = array();
        foreach ($objects as $object) {
            $certificate = $this->certificateOf($object);
            if ($certificate === null) {
                continue;
            }
            /*
             * Deduplicated on the fingerprint. Two services both
             * knowing a certificate is one certificate, and a count
             * that said two would be a count of who was asked.
             */
            $key = $certificate['fingerprint'] !== null
                ? $certificate['fingerprint']
                : ($certificate['subject'] . "\0"
                    . $certificate['not_before']);
            if (isset($certificates[$key])) {
                $held = $certificates[$key]['sources'];
                if (!in_array($certificate['module'], $held, true)) {
                    $certificates[$key]['sources'][] =
                        $certificate['module'];
                }
                continue;
            }
            $certificates[$key] = $certificate;
        }
        $certificates = array_values($certificates);
        usort($certificates, function ($a, $b) {
            return ($b['not_before'] ?? 0) - ($a['not_before'] ?? 0);
        });
        $newest = empty($certificates) ? null : $certificates[0];
        return array(
            'certificates' => $certificates,
            'count' => count($certificates),
            'newest' => $newest,
            /*
             * Whether anything served now is past its date. An expired
             * certificate still being served is a finding on its own,
             * and it is the one thing the compact form has room to say
             * beyond the count.
             */
            'expired' => $this->expiredCount($certificates),
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $certificates
     * @return int
     */
    private function expiredCount(array $certificates)
    {
        $now = time();
        $count = 0;
        foreach ($certificates as $certificate) {
            if ($certificate['not_after'] !== null
                && $certificate['not_after'] < $now
            ) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function certificateOf(array $object)
    {
        $subject = $this->firstValue($object, self::SUBJECT);
        $fingerprint = $this->firstValue($object, self::FINGERPRINT);
        $notBefore = $this->stamp(
            $this->value($object, 'validity-not-before')
        );
        $notAfter = $this->stamp(
            $this->value($object, 'validity-not-after')
        );
        if ($subject === null && $fingerprint === null
            && $notBefore === null
        ) {
            return null;
        }
        return array(
            'subject' => $subject,
            'issuer' => $this->firstValue($object, self::ISSUER),
            'fingerprint' => $fingerprint,
            'not_before' => $notBefore,
            'not_after' => $notAfter,
            'names' => $this->values($object, 'dns_names'),
            'self_signed' => $this->value($object, 'is_self_signed')
                ?? $this->value($object, 'self_signed'),
            'algorithm' => $this->value($object, 'signature_algorithm'),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
            'sources' => array($object['module'] ?? null),
        );
    }
}
