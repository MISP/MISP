<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class AttachmentScan extends AppModel
{
    public const TYPE_ATTRIBUTE = 'Attribute',
        TYPE_SHADOW_ATTRIBUTE = 'ShadowAttribute';

    // base64 encoded eicar.exe
    public const EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=';

    /**
     * List of supported object templates
     * @var string[]
     */
    public const SIGNATURE_TEMPLATES = [
        '4dbb56ef-4763-4c97-8696-a2bfc305cf8e', // av-signature
        '984c5c39-be7f-4e1e-b034-d3213bac51cb', // sb-signature
    ];

    /**
     * List of supported ways how to send data to module. From the most reliable to worst.
     * @var string[]
     */
    public const POSSIBLE_TYPES = [
        'attachment',
        'sha3-512',
        'sha3-384',
        'sha3-256',
        'sha3-224',
        'sha512',
        'sha512/224',
        'sha512/256',
        'sha384',
        'sha256',
        'sha224',
        'sha1',
        'md5',
    ];
}
