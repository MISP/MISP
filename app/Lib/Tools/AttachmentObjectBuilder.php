<?php
App::uses('CakeText', 'Utility');
App::uses('MispAttribute', 'Model');

/**
 * Dispatches an uploaded attachment to the appropriate object-template
 * handler. All handlers return a normalized payload of the shape:
 *
 *   [
 *       'Attribute'       => [],  // flat attributes to save directly
 *       'Object'          => [],  // objects (each with nested Attribute[]) to captureObject()
 *       'ObjectReference' => [],  // object references to smartSave()
 *   ]
 *
 * Most templates are handled via a declarative SPECS table + buildFromSpec().
 * Templates needing extra parsing (script, email, paste, report, forged/leaked-document,
 * original-imported-file, geojson, gpx) have small custom handlers.
 */
class AttachmentObjectBuilder
{
    /** @var MispAttribute */
    private $MispAttribute;

    /**
     * Declarative specs for the "boring" templates — payload slot + the common
     * file attributes (hashes / filename / size / mimetype / entropy / magic).
     * Keys: "<pool>:<template-name>".
     *
     * Known keys per spec:
     *   fallback_meta / fallback_desc   Used when the template isn't present in the DB.
     *   payload_relation, payload_type  Primary slot for the file bytes.
     *   encrypt                         If true, encrypt+zip as per the malware-sample flow.
     *   hashes                          Relations to populate with standard hashes.
     *   filename_relation               Relation for the original filename (null to skip).
     *   size_relation                   Relation for the size in bytes (null to skip).
     *   mimetype_relation               Relation for the mime type (null to skip).
     *   mimetype_type                   MISP type to use for mimetype ('mime-type' usually).
     *   entropy_relation                Relation for Shannon entropy (null to skip).
     *   magic_relation                  Relation for libmagic output (null to skip).
     *   extras                          Literal [relation => [type, value, to_ids?, disable_correlation?]].
     */
    private const SPECS = [
        // ------------------------------------------------------------ malicious
        'malicious:apk' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Apk object describing a file with meta-information',
            'payload_relation' => 'malware-sample',
            'payload_type' => 'malware-sample',
            'encrypt' => true,
            'hashes' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ssdeep', 'tlsh'],
            'filename_relation' => 'filename',
            'size_relation' => 'size-in-bytes',
            'mimetype_relation' => 'mimetype',
            'mimetype_type' => 'mime-type',
            'wants_lief' => true,
        ],
        'malicious:lnk' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'LNK object describing a Windows LNK binary file',
            'payload_relation' => 'malware-sample',
            'payload_type' => 'malware-sample',
            'encrypt' => true,
            'hashes' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'ssdeep', 'tlsh'],
            'filename_relation' => 'filename',
            'size_relation' => 'size-in-bytes',
            'entropy_relation' => 'entropy',
            'wants_lief' => true,
        ],
        'malicious:cs-beacon-config' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Cobalt Strike Beacon Config',
            'payload_relation' => 'encoded-data',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha256'],
            'size_relation' => 'encoded-length',
        ],
        'malicious:malware-config' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Malware configuration recovered or extracted from a malicious binary',
            'payload_relation' => 'file-config',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],
        'malicious:data-url' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'URL prefixed with the data: scheme',
            'payload_relation' => 'data',
            'payload_type' => 'malware-sample',
            'encrypt' => true,
            'hashes' => [],
            'mimetype_relation' => 'media-type',
            'mimetype_type' => 'mime-type',
            'extras' => [
                'base64' => ['type' => 'boolean', 'value' => '1', 'disable_correlation' => 1],
            ],
        ],
        'malicious:artifact' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Artifact capturing an array of bytes as base64',
            'payload_relation' => 'payload_bin',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha256', 'sha3-256', 'sha3-512', 'sha512', 'ssdeep', 'tlsh'],
            'mimetype_relation' => 'mime_type',
            'mimetype_type' => 'mime-type',
            'wants_lief' => true,
        ],
        'malicious:exploit' => [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Exploit object describing a program used to abuse vulnerabilities',
            'payload_relation' => 'exploit-as-attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
            'filename_relation' => 'filename',
        ],
        'malicious:exploit-poc' => [
            'fallback_meta' => 'vulnerability',
            'fallback_desc' => 'Exploit-poc describing a proof of concept of a vulnerability',
            'payload_relation' => 'poc',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],

        // -------------------------------------------------------- non_malicious
        'non_malicious:file' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'File object describing a file with meta-information',
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                         'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512',
                         'ssdeep', 'tlsh', 'imphash', 'authentihash', 'telfhash', 'vhash'],
            'filename_relation' => 'filename',
            'size_relation' => 'size-in-bytes',
            'mimetype_relation' => 'mimetype',
            'mimetype_type' => 'mime-type',
            'entropy_relation' => 'entropy',
            'magic_relation' => 'magic',
            'wants_lief' => true,
        ],
        'non_malicious:image' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Object describing an image file',
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
            'filename_relation' => 'filename',
        ],
        'non_malicious:meme-image' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Object describing a meme image',
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],
        'non_malicious:ocrized-image' => [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'OCRized image, including the original image and extracted text',
            'payload_relation' => 'image',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
            // ocr-text is required by template but needs an OCR dep; left empty.
        ],
        'non_malicious:sandbox-report' => [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Sandbox report',
            'payload_relation' => 'sandbox-file',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
            'extras' => [
                'sandbox-type' => ['type' => 'text', 'value' => 'uploaded', 'disable_correlation' => 1],
            ],
        ],
        'non_malicious:risk-assessment-report' => [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Risk assessment report',
            'payload_relation' => 'report-file',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],
        'non_malicious:phishing' => [
            'fallback_meta' => 'network',
            'fallback_desc' => 'Phishing screenshot / evidence',
            'payload_relation' => 'screenshot',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],
        'non_malicious:trusted-timestamp' => [
            'fallback_meta' => 'file',
            'fallback_desc' => 'A trusted timestamp',
            'payload_relation' => 'trusted-timestamp-response',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ],
    ];

    /**
     * Templates with dedicated custom handlers (their name → method).
     */
    private const CUSTOM_HANDLERS = [
        'malicious:file' => 'buildMaliciousFileDefault',
        'malicious:script' => 'buildMaliciousScript',
        'non_malicious:forged-document' => 'buildNonMaliciousForgedDocument',
        'non_malicious:leaked-document' => 'buildNonMaliciousLeakedDocument',
        'non_malicious:report' => 'buildNonMaliciousReport',
        'non_malicious:email' => 'buildNonMaliciousEmail',
        'non_malicious:paste' => 'buildNonMaliciousPaste',
        'non_malicious:original-imported-file' => 'buildNonMaliciousOriginalImportedFile',
        'non_malicious:iot-firmware' => 'buildNonMaliciousIotFirmware',
        'non_malicious:geojson' => 'buildNonMaliciousGeojson',
        'non_malicious:gpx' => 'buildNonMaliciousGpx',
    ];

    public function __construct(MispAttribute $mispAttribute)
    {
        $this->MispAttribute = $mispAttribute;
    }

    /**
     * @param string      $pool           'malicious' | 'non_malicious'
     * @param string|null $templateUuid   Curated template UUID, or null for the non-malicious flat-attachment sentinel.
     * @param int         $eventId
     * @param array       $attributeSettings
     * @param string      $filename
     * @param File        $tmpfile
     * @return array
     * @throws InvalidArgumentException
     */
    public function build($pool, $templateUuid, $eventId, array $attributeSettings, $filename, $tmpfile)
    {
        if ($pool === 'non_malicious' && ($templateUuid === null || $templateUuid === '')) {
            return $this->buildFlatAttachment($eventId, $attributeSettings, $filename, $tmpfile);
        }

        $entry = $this->resolveTemplate($pool, $templateUuid);
        $key = $pool . ':' . $entry['name'];

        if (isset(self::CUSTOM_HANDLERS[$key])) {
            $method = self::CUSTOM_HANDLERS[$key];
            return $this->$method($eventId, $attributeSettings, $filename, $tmpfile, $entry);
        }
        if (isset(self::SPECS[$key])) {
            return $this->buildFromSpec($eventId, $attributeSettings, $filename, $tmpfile, $entry, self::SPECS[$key]);
        }

        throw new InvalidArgumentException(sprintf(
            'Handler for attachment template "%s" (pool: %s) is not implemented yet.',
            $entry['name'], $pool
        ));
    }

    // ---------------------------------------------------------- resolution

    private function resolveTemplate($pool, $templateUuid)
    {
        $pools = MispAttribute::ATTACHMENT_OBJECT_TEMPLATES;
        if (!isset($pools[$pool])) {
            throw new InvalidArgumentException(sprintf('Unknown attachment pool "%s".', $pool));
        }
        $normalized = $templateUuid === '' ? null : $templateUuid;
        foreach ($pools[$pool] as $tpl) {
            if ($tpl['uuid'] === $normalized) {
                return $tpl;
            }
        }
        throw new InvalidArgumentException(sprintf(
            'Template "%s" is not a valid choice for the %s attachment pool.',
            $templateUuid === null ? '(none)' : $templateUuid, $pool
        ));
    }

    // ------------------------------------------------------- default paths

    private function buildMaliciousFileDefault($eventId, array $attributeSettings, $filename, $tmpfile, array $entry = null)
    {
        $advanced = !empty($attributeSettings['advanced']);
        $result = $advanced
            ? $this->MispAttribute->advancedAddMalwareSample($eventId, $attributeSettings, $filename, $tmpfile)
            : $this->MispAttribute->simpleAddMalwareSample($eventId, $attributeSettings, $filename, $tmpfile);
        return $this->normalize($result);
    }

    private function buildFlatAttachment($eventId, array $attributeSettings, $filename, $tmpfile)
    {
        $attribute = [
            'value' => $filename,
            'category' => isset($attributeSettings['category']) ? $attributeSettings['category'] : 'Other',
            'type' => 'attachment',
            'event_id' => $eventId,
            'data_raw' => $tmpfile->read(),
            'comment' => isset($attributeSettings['comment']) ? $attributeSettings['comment'] : '',
            'to_ids' => 0,
            'distribution' => isset($attributeSettings['distribution']) ? $attributeSettings['distribution'] : 0,
            'sharing_group_id' => isset($attributeSettings['sharing_group_id']) ? $attributeSettings['sharing_group_id'] : 0,
        ];
        return ['Attribute' => [$attribute], 'Object' => [], 'ObjectReference' => []];
    }

    // ----------------------------------------------------- spec-based build

    private function buildFromSpec($eventId, array $settings, $filename, $tmpfile, array $entry, array $spec)
    {
        $ctx = $this->prepareContext($filename, $tmpfile, !empty($spec['wants_lief']));
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);

        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        foreach ($this->buildStandardAttrs($eventId, $settings, $filename, $ctx, $spec) as $attr) {
            $object['Attribute'][] = $attr;
        }
        foreach ($this->buildExtras($eventId, $settings, $spec) as $attr) {
            $object['Attribute'][] = $attr;
        }

        $objects = [$object];
        $references = [];
        if (in_array($entry['name'], ['image', 'meme-image'], true)) {
            list($exifObject, $exifRef) = $this->buildExifObject($eventId, $settings, $tmpfile->path, $object['uuid']);
            if ($exifObject !== null) {
                $objects[] = $exifObject;
                $references[] = $exifRef;
            }
        }

        return ['Attribute' => [], 'Object' => $objects, 'ObjectReference' => $references];
    }

    private function buildObjectShell($eventId, array $entry, array $spec, array $settings)
    {
        $tpl = $this->loadObjectTemplate(
            $entry['uuid'],
            $entry['name'],
            isset($spec['fallback_meta']) ? $spec['fallback_meta'] : 'file',
            isset($spec['fallback_desc']) ? $spec['fallback_desc'] : $entry['description']
        );
        // Pre-assign a UUID so we can link this object from derived objects
        // (e.g. an exif object referencing an image object) without a second
        // round-trip through captureObject.
        return [
            'uuid' => CakeText::uuid(),
            'distribution' => isset($settings['distribution']) ? $settings['distribution'] : 0,
            'sharing_group_id' => isset($settings['sharing_group_id']) ? $settings['sharing_group_id'] : 0,
            'meta-category' => $tpl['ObjectTemplate']['meta-category'],
            'name' => $tpl['ObjectTemplate']['name'],
            'template_version' => $tpl['ObjectTemplate']['version'],
            'description' => $tpl['ObjectTemplate']['description'],
            'template_uuid' => $tpl['ObjectTemplate']['uuid'],
            'event_id' => $eventId,
            'comment' => isset($settings['comment']) ? $settings['comment'] : '',
            'Attribute' => [],
        ];
    }

    private function buildPayloadAttr($eventId, array $settings, $filename, array $ctx, array $spec)
    {
        $category = isset($settings['category']) ? $settings['category'] : 'Payload delivery';
        $malicious = !empty($spec['encrypt']);

        if ($malicious && $spec['payload_type'] === 'malware-sample') {
            $payload = $this->MispAttribute->encryptForMalwareSample(
                $filename, $ctx['content'], ['md5', 'sha1', 'sha256']
            );
            return $this->makeAttr(
                $eventId, 'malware-sample', $spec['payload_relation'],
                $filename . '|' . $payload['md5'], $category,
                ['to_ids' => 1, 'data_raw' => $payload['data_raw']]
            );
        }

        // Raw attachment (no encryption).
        return $this->makeAttr(
            $eventId, 'attachment', $spec['payload_relation'],
            $filename, $category,
            ['to_ids' => 0, 'data_raw' => $ctx['content']]
        );
    }

    private function buildStandardAttrs($eventId, array $settings, $filename, array $ctx, array $spec)
    {
        $out = [];
        $category = isset($settings['category']) ? $settings['category'] : 'Other';
        $toIdsOnHashes = !empty($spec['encrypt']) ? 1 : 0;

        if (!empty($spec['hashes'])) {
            foreach ($spec['hashes'] as $hashType) {
                if (!isset($ctx['hashes'][$hashType])) {
                    continue;
                }
                $out[] = $this->makeAttr(
                    $eventId, $hashType, $hashType, $ctx['hashes'][$hashType], $category,
                    ['to_ids' => $toIdsOnHashes]
                );
            }
        }
        if (!empty($spec['filename_relation'])) {
            $out[] = $this->makeAttr(
                $eventId, 'filename', $spec['filename_relation'], $filename, $category,
                ['to_ids' => 0]
            );
        }
        if (!empty($spec['size_relation'])) {
            $out[] = $this->makeAttr(
                $eventId, 'size-in-bytes', $spec['size_relation'], (string)$ctx['size'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        if (!empty($spec['mimetype_relation']) && !empty($ctx['mimetype'])) {
            $type = isset($spec['mimetype_type']) ? $spec['mimetype_type'] : 'mime-type';
            $out[] = $this->makeAttr(
                $eventId, $type, $spec['mimetype_relation'], $ctx['mimetype'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        if (!empty($spec['entropy_relation'])) {
            $out[] = $this->makeAttr(
                $eventId, 'float', $spec['entropy_relation'], (string)$ctx['entropy'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        if (!empty($spec['magic_relation']) && !empty($ctx['magic'])) {
            $out[] = $this->makeAttr(
                $eventId, 'text', $spec['magic_relation'], $ctx['magic'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        return $out;
    }

    private function buildExtras($eventId, array $settings, array $spec)
    {
        $out = [];
        if (empty($spec['extras']) || !is_array($spec['extras'])) {
            return $out;
        }
        $category = isset($settings['category']) ? $settings['category'] : 'Other';
        foreach ($spec['extras'] as $relation => $cfg) {
            $opts = [
                'to_ids' => isset($cfg['to_ids']) ? $cfg['to_ids'] : 0,
                'disable_correlation' => isset($cfg['disable_correlation']) ? $cfg['disable_correlation'] : 0,
            ];
            $out[] = $this->makeAttr($eventId, $cfg['type'], $relation, $cfg['value'], $category, $opts);
        }
        return $out;
    }

    // -------------------------------------------------------- custom handlers

    private function buildMaliciousScript($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Object describing a computer program',
            'payload_relation' => 'script-as-attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
            'filename_relation' => 'filename',
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        foreach ($this->buildStandardAttrs($eventId, $settings, $filename, $ctx, $spec) as $a) {
            $object['Attribute'][] = $a;
        }

        $language = $this->detectScriptLanguage($filename, $ctx);
        if ($language !== null) {
            $object['Attribute'][] = $this->makeAttr(
                $eventId, 'text', 'language', $language, 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        if ($this->looksLikeText($ctx) && $ctx['size'] <= 256 * 1024) {
            $object['Attribute'][] = $this->makeAttr(
                $eventId, 'text', 'script', $ctx['content'],
                isset($settings['category']) ? $settings['category'] : 'Payload delivery',
                ['to_ids' => 0]
            );
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousForgedDocument($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        return $this->buildDocumentStyleObject($eventId, $settings, $filename, $tmpfile, $entry,
            'file', 'Object describing a forged document');
    }

    private function buildNonMaliciousLeakedDocument($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        return $this->buildDocumentStyleObject($eventId, $settings, $filename, $tmpfile, $entry,
            'file', 'Object describing a leaked document');
    }

    /**
     * forged-document / leaked-document share almost the same shape: attachment +
     * document-name (text) populated with the original filename.
     */
    private function buildDocumentStyleObject($eventId, array $settings, $filename, $tmpfile, array $entry, $meta, $desc)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => $meta,
            'fallback_desc' => $desc,
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        $object['Attribute'][] = $this->makeAttr(
            $eventId, 'text', 'document-name', $filename, 'Other',
            ['to_ids' => 0, 'disable_correlation' => 1]
        );
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousReport($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Report object describing a report along with its metadata',
            'payload_relation' => 'report-file',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        // title is required-one-of; use filename so the object is valid out of the box.
        $object['Attribute'][] = $this->makeAttr(
            $eventId, 'text', 'title', $filename, 'Other',
            ['to_ids' => 0, 'disable_correlation' => 1]
        );
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousEmail($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if ($ext === 'eml') {
            $relation = 'eml';
        } elseif ($ext === 'msg') {
            $relation = 'msg';
        } elseif (in_array($ext, ['png', 'jpg', 'jpeg', 'webp', 'gif'], true)) {
            $relation = 'screenshot';
        } else {
            $relation = 'email-body-attachment';
        }
        $spec = [
            'fallback_meta' => 'network',
            'fallback_desc' => 'Email object describing an email with meta-information',
            'payload_relation' => $relation,
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousPaste($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'misc',
            'fallback_desc' => 'Paste or similar post from a website',
            'payload_relation' => 'paste-file',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        $object['Attribute'][] = $this->makeAttr(
            $eventId, 'text', 'title', $filename, 'Other',
            ['to_ids' => 0, 'disable_correlation' => 1]
        );
        if ($this->looksLikeText($ctx) && $ctx['size'] <= 512 * 1024) {
            $object['Attribute'][] = $this->makeAttr(
                $eventId, 'text', 'paste', $ctx['content'], 'Other',
                ['to_ids' => 0]
            );
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousIotFirmware($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'iot',
            'fallback_desc' => 'A firmware for an IoT device',
            'payload_relation' => 'firmware',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
            'size_relation' => 'size-in-bytes',
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        foreach ($this->buildStandardAttrs($eventId, $settings, $filename, $ctx, $spec) as $a) {
            $object['Attribute'][] = $a;
        }
        // iot-firmware template uses `filename` with misp-attribute type `text`, not the
        // standard `filename` type — can't route through buildStandardAttrs.
        $object['Attribute'][] = $this->makeAttr(
            $eventId, 'text', 'filename', $filename, 'Other',
            ['to_ids' => 0, 'disable_correlation' => 1]
        );
        if (!empty($ctx['mimetype'])) {
            $object['Attribute'][] = $this->makeAttr(
                $eventId, 'text', 'format', $ctx['mimetype'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousOriginalImportedFile($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'file',
            'fallback_desc' => 'Object describing the original file used to import data in MISP',
            'payload_relation' => 'imported-sample',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => [],
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        if (!empty($ctx['mimetype'])) {
            $object['Attribute'][] = $this->makeAttr(
                $eventId, 'text', 'format', $ctx['mimetype'], 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousGeojson($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'file',
            'fallback_desc' => 'GeoJSON file containing geographic data structures',
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha256'],
            'filename_relation' => 'filename',
            'size_relation' => 'size-in-bytes',
            'mimetype_relation' => 'mime-type',
            'mimetype_type' => 'mime-type',
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        foreach ($this->buildStandardAttrs($eventId, $settings, $filename, $ctx, $spec) as $a) {
            $object['Attribute'][] = $a;
        }
        foreach ($this->extractGeojsonAttrs($eventId, $ctx) as $a) {
            $object['Attribute'][] = $a;
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    private function buildNonMaliciousGpx($eventId, array $settings, $filename, $tmpfile, array $entry)
    {
        $ctx = $this->prepareContext($filename, $tmpfile);
        $spec = [
            'fallback_meta' => 'file',
            'fallback_desc' => 'GPX (GPS Exchange Format) file',
            'payload_relation' => 'attachment',
            'payload_type' => 'attachment',
            'encrypt' => false,
            'hashes' => ['md5', 'sha1', 'sha256'],
            'filename_relation' => 'filename',
            'size_relation' => 'size-in-bytes',
            'mimetype_relation' => 'mime-type',
            'mimetype_type' => 'mime-type',
        ];
        $object = $this->buildObjectShell($eventId, $entry, $spec, $settings);
        $object['Attribute'][] = $this->buildPayloadAttr($eventId, $settings, $filename, $ctx, $spec);
        foreach ($this->buildStandardAttrs($eventId, $settings, $filename, $ctx, $spec) as $a) {
            $object['Attribute'][] = $a;
        }
        foreach ($this->extractGpxAttrs($eventId, $ctx) as $a) {
            $object['Attribute'][] = $a;
        }
        return ['Attribute' => [], 'Object' => [$object], 'ObjectReference' => []];
    }

    // ---------------------------------------------- custom-extraction helpers

    private function extractGeojsonAttrs($eventId, array $ctx)
    {
        $out = [];
        $decoded = json_decode($ctx['content'], true);
        if (!is_array($decoded)) {
            return $out;
        }
        $features = [];
        if (isset($decoded['type']) && $decoded['type'] === 'FeatureCollection' && isset($decoded['features'])) {
            $features = $decoded['features'];
        } elseif (isset($decoded['type']) && $decoded['type'] === 'Feature') {
            $features = [$decoded];
        }
        if (!empty($features)) {
            $out[] = $this->makeAttr(
                $eventId, 'counter', 'feature-count', (string)count($features), 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        $geomTypes = [];
        $minLat = $maxLat = $minLon = $maxLon = null;
        foreach ($features as $feature) {
            if (!empty($feature['geometry']['type'])) {
                $geomTypes[$feature['geometry']['type']] = true;
            }
            if (!empty($feature['geometry']['coordinates'])) {
                $this->scanCoordinates($feature['geometry']['coordinates'], $minLat, $maxLat, $minLon, $maxLon);
            }
        }
        foreach (array_keys($geomTypes) as $gt) {
            $out[] = $this->makeAttr(
                $eventId, 'text', 'geometry-types', $gt, 'Other',
                ['to_ids' => 0, 'disable_correlation' => 1]
            );
        }
        if ($minLat !== null) {
            $out[] = $this->makeAttr($eventId, 'float', 'min-latitude', (string)$minLat, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'max-latitude', (string)$maxLat, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'min-longitude', (string)$minLon, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'max-longitude', (string)$maxLon, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
        }
        return $out;
    }

    private function scanCoordinates($coords, &$minLat, &$maxLat, &$minLon, &$maxLon)
    {
        if (!is_array($coords) || empty($coords)) {
            return;
        }
        if (is_numeric($coords[0]) && isset($coords[1]) && is_numeric($coords[1])) {
            $lon = (float)$coords[0];
            $lat = (float)$coords[1];
            $minLat = $minLat === null ? $lat : min($minLat, $lat);
            $maxLat = $maxLat === null ? $lat : max($maxLat, $lat);
            $minLon = $minLon === null ? $lon : min($minLon, $lon);
            $maxLon = $maxLon === null ? $lon : max($maxLon, $lon);
            return;
        }
        foreach ($coords as $c) {
            $this->scanCoordinates($c, $minLat, $maxLat, $minLon, $maxLon);
        }
    }

    private function extractGpxAttrs($eventId, array $ctx)
    {
        $out = [];
        $prev = libxml_use_internal_errors(true);
        $xml = @simplexml_load_string($ctx['content']);
        libxml_use_internal_errors($prev);
        if ($xml === false) {
            return $out;
        }

        $attrs = $xml->attributes();
        if (isset($attrs['version']) && (string)$attrs['version'] !== '') {
            $out[] = $this->makeAttr($eventId, 'text', 'gpx-version', (string)$attrs['version'], 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
        }
        if (isset($attrs['creator']) && (string)$attrs['creator'] !== '') {
            $out[] = $this->makeAttr($eventId, 'text', 'creator', (string)$attrs['creator'], 'Other', ['to_ids' => 0]);
        }
        if (isset($xml->metadata)) {
            if (!empty((string)$xml->metadata->name)) {
                $out[] = $this->makeAttr($eventId, 'text', 'name', (string)$xml->metadata->name, 'Other', ['to_ids' => 0]);
            }
            if (!empty((string)$xml->metadata->desc)) {
                $out[] = $this->makeAttr($eventId, 'text', 'description-text', (string)$xml->metadata->desc, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            }
            if (!empty((string)$xml->metadata->author->name)) {
                $out[] = $this->makeAttr($eventId, 'text', 'author', (string)$xml->metadata->author->name, 'Other', ['to_ids' => 0]);
            }
            if (!empty((string)$xml->metadata->time)) {
                $out[] = $this->makeAttr($eventId, 'datetime', 'time', (string)$xml->metadata->time, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            }
        }

        $counts = [
            'waypoint-count' => count($xml->wpt ?? []),
            'route-count' => count($xml->rte ?? []),
            'track-count' => count($xml->trk ?? []),
        ];
        foreach ($counts as $rel => $n) {
            if ($n > 0) {
                $out[] = $this->makeAttr($eventId, 'counter', $rel, (string)$n, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            }
        }

        $segs = 0;
        $minLat = $maxLat = $minLon = $maxLon = null;
        $startTime = $endTime = null;
        foreach (['wpt', 'rte', 'trk'] as $kind) {
            foreach ($xml->$kind as $node) {
                if ($kind === 'trk') {
                    foreach ($node->trkseg as $seg) {
                        $segs++;
                        foreach ($seg->trkpt as $pt) {
                            $this->recordGpxPoint($pt, $minLat, $maxLat, $minLon, $maxLon, $startTime, $endTime);
                        }
                    }
                } elseif ($kind === 'rte') {
                    foreach ($node->rtept as $pt) {
                        $this->recordGpxPoint($pt, $minLat, $maxLat, $minLon, $maxLon, $startTime, $endTime);
                    }
                } else {
                    $this->recordGpxPoint($node, $minLat, $maxLat, $minLon, $maxLon, $startTime, $endTime);
                }
            }
        }
        if ($segs > 0) {
            $out[] = $this->makeAttr($eventId, 'counter', 'track-segment-count', (string)$segs, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
        }
        if ($minLat !== null) {
            $out[] = $this->makeAttr($eventId, 'float', 'min-latitude', (string)$minLat, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'max-latitude', (string)$maxLat, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'min-longitude', (string)$minLon, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'float', 'max-longitude', (string)$maxLon, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
        }
        if ($startTime !== null) {
            $out[] = $this->makeAttr($eventId, 'datetime', 'start-time', $startTime, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
            $out[] = $this->makeAttr($eventId, 'datetime', 'end-time', $endTime, 'Other', ['to_ids' => 0, 'disable_correlation' => 1]);
        }
        return $out;
    }

    private function recordGpxPoint($pt, &$minLat, &$maxLat, &$minLon, &$maxLon, &$startTime, &$endTime)
    {
        $a = $pt->attributes();
        if (isset($a['lat']) && isset($a['lon'])) {
            $lat = (float)$a['lat'];
            $lon = (float)$a['lon'];
            $minLat = $minLat === null ? $lat : min($minLat, $lat);
            $maxLat = $maxLat === null ? $lat : max($maxLat, $lat);
            $minLon = $minLon === null ? $lon : min($minLon, $lon);
            $maxLon = $maxLon === null ? $lon : max($maxLon, $lon);
        }
        if (!empty((string)$pt->time)) {
            $t = (string)$pt->time;
            if ($startTime === null || strcmp($t, $startTime) < 0) $startTime = $t;
            if ($endTime === null || strcmp($t, $endTime) > 0) $endTime = $t;
        }
    }

    // ---------------------------------------------------- generic helpers

    private function prepareContext($filename, $tmpfile, $wantsLief = false)
    {
        $content = $tmpfile->read();
        if ($content === false) {
            $content = '';
        }
        $hashes = $this->computeHashes($content);
        if ($wantsLief) {
            // LIEF-backed hashes first so that PECL results win on conflict.
            $hashes = array_merge($hashes, $this->computeLiefHashes($tmpfile->path));
        }
        $hashes = array_merge($hashes, $this->computeExtensionHashes($content));
        return [
            'content' => $content,
            'size' => strlen($content),
            'hashes' => $hashes,
            'mimetype' => $this->detectMime($content),
            'magic' => $this->detectMagic($content),
            'entropy' => $this->shannonEntropy($content),
        ];
    }

    /**
     * Fuzzy / locality hashes that depend on optional PHP extensions.
     * Silently skipped when the extension isn't loaded.
     */
    private function computeExtensionHashes($content)
    {
        $out = [];
        if (function_exists('ssdeep_fuzzy_hash')) {
            $h = @ssdeep_fuzzy_hash($content);
            if (is_string($h) && $h !== '') {
                $out['ssdeep'] = $h;
            }
        }
        // No canonical PECL tlsh extension; some installs expose a `tlsh_hash`
        // function or a Tlsh class. Probe for either and skip otherwise.
        if (function_exists('tlsh_hash')) {
            $h = @tlsh_hash($content);
            if (is_string($h) && $h !== '') {
                $out['tlsh'] = $h;
            }
        } elseif (class_exists('Tlsh')) {
            try {
                $t = new Tlsh();
                if (method_exists($t, 'update') && method_exists($t, 'final') && method_exists($t, 'getHash')) {
                    $t->update($content);
                    $t->final();
                    $h = $t->getHash();
                    if (is_string($h) && $h !== '') {
                        $out['tlsh'] = $h;
                    }
                }
            } catch (Exception $e) {
                // ignore
            }
        }
        return $out;
    }

    /**
     * Invokes the advanced-extraction helper (generate_file_objects.py) and picks
     * the file-level LIEF/pydeep hashes out of the returned objects. Same deps
     * and same subprocess entry point as the existing malicious/file advanced
     * flow — never called unless the spec marks `wants_lief` and the check shows
     * at least pymisp + one hashing tool available.
     *
     * @return array<string,string>
     */
    private function computeLiefHashes($filePath)
    {
        $tools = $this->MispAttribute->advancedExtractionTools();
        if (empty($tools['pymisp'])) {
            return [];
        }
        if (empty($tools['lief']) && empty($tools['pydeep'])) {
            // Neither LIEF nor pydeep → nothing to add over what we already have.
            return [];
        }
        try {
            $result = $this->MispAttribute->runAdvancedExtraction($filePath);
        } catch (Exception $e) {
            return [];
        }
        $objects = isset($result['objects']) ? $result['objects']
                 : (isset($result['Object']) ? $result['Object'] : []);
        $wanted = ['ssdeep', 'tlsh', 'imphash', 'authentihash', 'telfhash', 'vhash', 'pehash', 'impfuzzy'];
        $out = [];
        foreach ($objects as $obj) {
            $name = isset($obj['name']) ? $obj['name'] : null;
            if ($name !== null && $name !== 'file') {
                continue; // we only harvest from the base file object, not pe/elf children
            }
            $attrs = isset($obj['Attribute']) ? $obj['Attribute'] : [];
            foreach ($attrs as $attr) {
                $type = isset($attr['type']) ? $attr['type'] : null;
                if (in_array($type, $wanted, true) && !empty($attr['value'])) {
                    $out[$type] = $attr['value'];
                }
            }
        }
        return $out;
    }

    /**
     * Builds a MISP `exif` object (UUID cb355d27-...) linked via an
     * "extracted-from" ObjectReference to the uploaded image. Returns
     * [Object, ObjectReference] or [null, null] when the exif extension is
     * absent, the file has no EXIF metadata, or every tag got filtered out.
     */
    private function buildExifObject($eventId, array $settings, $filePath, $parentUuid)
    {
        if (!function_exists('exif_read_data')) {
            return [null, null];
        }
        $data = @exif_read_data($filePath, 'ANY_TAG', true, false);
        if ($data === false || !is_array($data)) {
            return [null, null];
        }
        unset($data['THUMBNAIL']);
        $clean = $this->filterExifPrintable($data);
        if (empty($clean)) {
            return [null, null];
        }

        $attrs = $this->buildExifAttributes($eventId, $clean);
        if (empty($attrs)) {
            return [null, null];
        }

        $tpl = $this->loadObjectTemplate(
            'cb355d27-e481-42e1-8c2b-fb6998289426',
            'exif',
            'file',
            'Object describing EXIF metadata extracted from image files.'
        );
        $exifUuid = CakeText::uuid();
        $object = [
            'uuid' => $exifUuid,
            'distribution' => isset($settings['distribution']) ? $settings['distribution'] : 0,
            'sharing_group_id' => isset($settings['sharing_group_id']) ? $settings['sharing_group_id'] : 0,
            'meta-category' => $tpl['ObjectTemplate']['meta-category'],
            'name' => $tpl['ObjectTemplate']['name'],
            'template_version' => $tpl['ObjectTemplate']['version'],
            'description' => $tpl['ObjectTemplate']['description'],
            'template_uuid' => $tpl['ObjectTemplate']['uuid'],
            'event_id' => $eventId,
            'comment' => '',
            'Attribute' => $attrs,
        ];
        $reference = [
            'uuid' => CakeText::uuid(),
            'object_uuid' => $exifUuid,
            'referenced_uuid' => $parentUuid,
            'relationship_type' => 'extracted-from',
            'comment' => '',
        ];
        return [$object, $reference];
    }

    private function buildExifAttributes($eventId, array $clean)
    {
        $attrs = [];
        $cat = 'Other';
        $opts = ['to_ids' => 0, 'disable_correlation' => 1];

        // Plain text fields. Lists are tried in order; first non-empty wins.
        $textMap = [
            'artist' => ['IFD0.Artist', 'EXIF.Artist'],
            'copyright' => ['IFD0.Copyright'],
            'image-description' => ['IFD0.ImageDescription'],
            'make' => ['IFD0.Make'],
            'model' => ['IFD0.Model'],
            'software' => ['IFD0.Software'],
            'lens-model' => ['EXIF.LensModel', 'EXIF.UndefinedTag:0xA434'],
            'exposure-time' => ['EXIF.ExposureTime'],
            'user-comment' => ['EXIF.UserComment', 'COMPUTED.UserComment'],
        ];
        foreach ($textMap as $relation => $paths) {
            $v = $this->digExifFirst($clean, $paths);
            if ($v !== null && $v !== '' && !is_array($v)) {
                $attrs[] = $this->makeAttr($eventId, 'text', $relation, (string)$v, $cat, $opts);
            }
        }

        // Integers and bitmaps that the template stores as text.
        foreach (['orientation' => 'IFD0.Orientation', 'flash' => 'EXIF.Flash'] as $relation => $path) {
            $v = $this->digExifFirst($clean, [$path]);
            if ($v !== null && !is_array($v)) {
                $attrs[] = $this->makeAttr($eventId, 'text', $relation, (string)$v, $cat, $opts);
            }
        }

        // Datetimes — EXIF format is "YYYY:MM:DD HH:MM:SS", MISP expects ISO.
        foreach ([
            'datetime-original' => 'EXIF.DateTimeOriginal',
            'datetime-digitized' => 'EXIF.DateTimeDigitized',
        ] as $relation => $path) {
            $v = $this->digExifFirst($clean, [$path]);
            $norm = $this->normalizeExifDatetime($v);
            if ($norm !== null) {
                $attrs[] = $this->makeAttr($eventId, 'datetime', $relation, $norm, $cat, $opts);
            }
        }
        $gpsDate = $this->digExifFirst($clean, ['GPS.GPSDateStamp']);
        $norm = $this->normalizeExifDate($gpsDate);
        if ($norm !== null) {
            $attrs[] = $this->makeAttr($eventId, 'datetime', 'gps-date-stamp', $norm, $cat, $opts);
        }

        // Rational floats (PHP reports these as "numerator/denominator" strings).
        foreach (['f-number' => 'EXIF.FNumber', 'focal-length' => 'EXIF.FocalLength'] as $relation => $path) {
            $v = $this->digExifFirst($clean, [$path]);
            $f = $this->parseExifRational($v);
            if ($f !== null) {
                $attrs[] = $this->makeAttr($eventId, 'float', $relation, (string)$f, $cat, $opts);
            }
        }

        // GPS altitude — Ref=1 means below sea level.
        $alt = $this->parseExifRational($this->digExifFirst($clean, ['GPS.GPSAltitude']));
        if ($alt !== null) {
            $altRef = $this->digExifFirst($clean, ['GPS.GPSAltitudeRef']);
            if ($altRef === 1 || $altRef === '1') {
                $alt = -$alt;
            }
            $attrs[] = $this->makeAttr($eventId, 'float', 'gps-altitude', (string)$alt, $cat, $opts);
        }

        // ISO — sometimes a plain int, sometimes an array of ints.
        $iso = $this->digExifFirst($clean, ['EXIF.ISOSpeedRatings']);
        if (is_array($iso) && isset($iso[0])) {
            $iso = $iso[0];
        }
        if (is_numeric($iso)) {
            $attrs[] = $this->makeAttr($eventId, 'integer', 'iso-speed-ratings', (string)(int)$iso, $cat, $opts);
        }

        // GPS latitude / longitude — DMS rationals to decimal degrees.
        $lat = $this->extractExifGpsCoord($clean, 'Latitude');
        if ($lat !== null) {
            $attrs[] = $this->makeAttr($eventId, 'float', 'gps-latitude', (string)$lat, $cat, $opts);
        }
        $lon = $this->extractExifGpsCoord($clean, 'Longitude');
        if ($lon !== null) {
            $attrs[] = $this->makeAttr($eventId, 'float', 'gps-longitude', (string)$lon, $cat, $opts);
        }

        // raw-output — full filtered dump as a JSON blob for anything the
        // typed mapping above doesn't surface.
        $json = @json_encode($clean, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json !== false && $json !== '' && $json !== 'null') {
            $attrs[] = $this->makeAttr($eventId, 'text', 'raw-output', $json, $cat, $opts);
        }

        return $attrs;
    }

    private function digExifFirst($data, array $paths)
    {
        foreach ($paths as $path) {
            $parts = explode('.', $path);
            $cur = $data;
            foreach ($parts as $p) {
                if (!is_array($cur) || !array_key_exists($p, $cur)) {
                    $cur = null;
                    break;
                }
                $cur = $cur[$p];
            }
            if ($cur !== null && $cur !== '') {
                return $cur;
            }
        }
        return null;
    }

    private function parseExifRational($v)
    {
        if ($v === null) {
            return null;
        }
        if (is_numeric($v)) {
            return (float)$v;
        }
        if (is_string($v) && preg_match('/^(-?\d+(?:\.\d+)?)\s*\/\s*(-?\d+(?:\.\d+)?)$/', $v, $m)) {
            $den = (float)$m[2];
            if ($den == 0.0) {
                return null;
            }
            return (float)$m[1] / $den;
        }
        return null;
    }

    private function extractExifGpsCoord(array $data, $kind)
    {
        $dms = $this->digExifFirst($data, ["GPS.GPS{$kind}"]);
        if (!is_array($dms) || count($dms) < 3) {
            return null;
        }
        $deg = $this->parseExifRational($dms[0]);
        $min = $this->parseExifRational($dms[1]);
        $sec = $this->parseExifRational($dms[2]);
        if ($deg === null || $min === null || $sec === null) {
            return null;
        }
        $decimal = $deg + $min / 60.0 + $sec / 3600.0;
        $ref = $this->digExifFirst($data, ["GPS.GPS{$kind}Ref"]);
        if (is_string($ref)) {
            $ref = strtoupper($ref);
            if ($ref === 'S' || $ref === 'W') {
                $decimal = -$decimal;
            }
        }
        return round($decimal, 6);
    }

    private function normalizeExifDatetime($v)
    {
        if (!is_string($v) || $v === '') {
            return null;
        }
        if (preg_match('/^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/', $v, $m)) {
            return sprintf('%s-%s-%sT%s:%s:%s', $m[1], $m[2], $m[3], $m[4], $m[5], $m[6]);
        }
        return null;
    }

    private function normalizeExifDate($v)
    {
        if (!is_string($v) || $v === '') {
            return null;
        }
        if (preg_match('/^(\d{4}):(\d{2}):(\d{2})$/', $v, $m)) {
            return sprintf('%s-%s-%s', $m[1], $m[2], $m[3]);
        }
        return null;
    }

    private function filterExifPrintable($data)
    {
        if (is_array($data)) {
            $out = [];
            foreach ($data as $k => $v) {
                $filtered = $this->filterExifPrintable($v);
                if ($filtered !== null && $filtered !== '' && $filtered !== []) {
                    $out[$k] = $filtered;
                }
            }
            return $out;
        }
        if (is_string($data)) {
            // Drop strings that are mostly non-printable (likely binary).
            if (!mb_check_encoding($data, 'UTF-8')) {
                return null;
            }
            if (preg_match('/[^\P{C}\n\r\t]/u', $data)) {
                return null;
            }
            return $data;
        }
        if (is_int($data) || is_float($data) || is_bool($data)) {
            return $data;
        }
        return null;
    }

    private function computeHashes($content)
    {
        $out = [];
        $available = hash_algos();
        foreach (['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                  'sha512/224', 'sha512/256',
                  'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'] as $algo) {
            if (in_array($algo, $available, true)) {
                $out[$algo] = hash($algo, $content);
            }
        }
        return $out;
    }

    private function detectMime($content)
    {
        if (!function_exists('finfo_open')) {
            return null;
        }
        $f = @finfo_open(FILEINFO_MIME_TYPE);
        if ($f === false) return null;
        $mime = @finfo_buffer($f, $content);
        finfo_close($f);
        return $mime ?: null;
    }

    private function detectMagic($content)
    {
        if (!function_exists('finfo_open')) {
            return null;
        }
        $f = @finfo_open(FILEINFO_NONE);
        if ($f === false) return null;
        $magic = @finfo_buffer($f, $content);
        finfo_close($f);
        return $magic ?: null;
    }

    private function shannonEntropy($content)
    {
        $len = strlen($content);
        if ($len === 0) {
            return 0.0;
        }
        $freq = count_chars($content, 1);
        $entropy = 0.0;
        foreach ($freq as $cnt) {
            $p = $cnt / $len;
            $entropy -= $p * log($p, 2);
        }
        return round($entropy, 4);
    }

    private function loadObjectTemplate($uuid, $fallbackName, $fallbackMeta, $fallbackDesc)
    {
        $ObjectTemplate = $this->MispAttribute->Object->ObjectTemplate;
        $current = $ObjectTemplate->find('first', [
            'fields' => ['MAX(version) AS version', 'uuid'],
            'conditions' => ['uuid' => $uuid],
            'recursive' => -1,
            'group' => ['uuid'],
        ]);
        if (!empty($current)) {
            $tpl = $ObjectTemplate->find('first', [
                'conditions' => [
                    'ObjectTemplate.uuid' => $uuid,
                    'ObjectTemplate.version' => $current[0]['version'],
                ],
                'recursive' => -1,
            ]);
            if (!empty($tpl)) {
                return $tpl;
            }
        }
        return ['ObjectTemplate' => [
            'meta-category' => $fallbackMeta,
            'name' => $fallbackName,
            'uuid' => $uuid,
            'version' => 1,
            'description' => $fallbackDesc,
        ]];
    }

    private function makeAttr($eventId, $type, $relation, $value, $category, array $opts = [])
    {
        $attr = [
            'distribution' => 5,
            'category' => $category,
            'type' => $type,
            'to_ids' => isset($opts['to_ids']) ? (int)$opts['to_ids'] : 0,
            'disable_correlation' => isset($opts['disable_correlation']) ? (int)$opts['disable_correlation'] : 0,
            'event_id' => $eventId,
            'object_relation' => $relation,
            'value' => $value,
        ];
        if (isset($opts['data_raw'])) {
            $attr['data_raw'] = $opts['data_raw'];
        }
        return $attr;
    }

    private function normalize($result)
    {
        if (!is_array($result)) {
            return ['Attribute' => [], 'Object' => [], 'ObjectReference' => []];
        }
        return [
            'Attribute' => isset($result['Attribute']) ? $result['Attribute'] : [],
            'Object' => isset($result['Object']) ? $result['Object'] : [],
            'ObjectReference' => isset($result['ObjectReference']) ? $result['ObjectReference'] : [],
        ];
    }

    private function looksLikeText(array $ctx)
    {
        if (empty($ctx['mimetype'])) {
            return false;
        }
        return strpos($ctx['mimetype'], 'text/') === 0
            || in_array($ctx['mimetype'], ['application/json', 'application/xml', 'application/javascript'], true);
    }

    /**
     * Best-effort language guess from filename extension. Returns null when unknown.
     * A richer classifier (shebang inspection, `file --mime`, source-highlighter) would
     * be more accurate but requires external tooling.
     */
    private function detectScriptLanguage($filename, array $ctx)
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        static $map = [
            'py' => 'python', 'pyc' => 'python', 'pyw' => 'python',
            'sh' => 'bash', 'bash' => 'bash', 'zsh' => 'zsh',
            'ps1' => 'powershell', 'psm1' => 'powershell', 'psd1' => 'powershell',
            'js' => 'javascript', 'mjs' => 'javascript', 'cjs' => 'javascript',
            'ts' => 'typescript',
            'rb' => 'ruby', 'php' => 'php', 'pl' => 'perl', 'lua' => 'lua',
            'rs' => 'rust', 'go' => 'go', 'c' => 'c', 'cpp' => 'c++', 'cs' => 'c#',
            'java' => 'java', 'kt' => 'kotlin', 'swift' => 'swift',
            'vbs' => 'vbscript', 'bat' => 'batch', 'cmd' => 'batch',
            'sql' => 'sql', 'r' => 'r', 'nse' => 'lua',
        ];
        if (isset($map[$ext])) {
            return $map[$ext];
        }
        // Fallback: inspect the first bytes for a shebang.
        $head = substr($ctx['content'], 0, 256);
        if (strpos($head, "#!") === 0) {
            if (stripos($head, 'python') !== false) return 'python';
            if (stripos($head, 'bash') !== false) return 'bash';
            if (stripos($head, 'node') !== false) return 'javascript';
            if (stripos($head, 'perl') !== false) return 'perl';
            if (stripos($head, 'ruby') !== false) return 'ruby';
            if (stripos($head, 'lua') !== false) return 'lua';
            if (stripos($head, '/sh') !== false) return 'sh';
        }
        return null;
    }
}
