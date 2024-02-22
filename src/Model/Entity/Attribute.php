<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Attribute extends AppModel
{
    public const EDITABLE_FIELDS = [
        'timestamp',
        'category',
        'type',
        'value',
        'value1',
        'value2',
        'to_ids',
        'comment',
        'distribution',
        'sharing_group_id',
        'deleted',
        'disable_correlation',
        'first_seen',
        'last_seen',
    ];

    // if these then a category may have upload to be zipped
    public const ZIPPED_DEFINITION = ['malware-sample'];

    // if these then a category may have upload
    public const UPLOAD_DEFINITIONS = ['attachment'];

    // skip Correlation for the following types
    public const NON_CORRELATING_TYPES = [
        'comment',
        'http-method',
        'aba-rtn',
        'gender',
        'counter',
        'float',
        'port',
        'nationality',
        'cortex',
        'boolean',
        'anonymised'
    ];

    public const PRIMARY_ONLY_CORRELATING_TYPES = [
        'ip-src|port',
        'ip-dst|port',
        'hostname|port',
    ];

    public const CAPTURE_FIELDS = [
        'event_id',
        'category',
        'type',
        'value',
        'value1',
        'value2',
        'to_ids',
        'uuid',
        'timestamp',
        'distribution',
        'comment',
        'sharing_group_id',
        'deleted',
        'disable_correlation',
        'object_id',
        'object_relation',
        'first_seen',
        'last_seen'
    ];

    public const FILE_HASH_TYPES = [
        'md5' => 32,
        'sha1' => 40,
        'sha256' => 64,
        'sha512' => 128,
    ];

    // typeGroupings are a mapping to high level groups for attributes
    // for example, IP addresses, domain names, hostnames and e-mail addresses are network related attribute types
    // whilst filenames and hashes are file related attribute types
    // This helps generate quick filtering for the event view, but we may reuse this and enhance it in the future for other uses (such as the API?)
    public const TYPE_GROUPINGS = [
        'file' => ['attachment', 'pattern-in-file', 'filename-pattern', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha512/224', 'sha512/256', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512', 'ssdeep', 'imphash', 'telfhash', 'impfuzzy', 'authentihash', 'vhash', 'pehash', 'tlsh', 'cdhash', 'filename', 'filename|md5', 'filename|sha1', 'filename|sha224', 'filename|sha256', 'filename|sha384', 'filename|sha512', 'filename|sha512/224', 'filename|sha512/256', 'filename|sha3-224', 'filename|sha3-256', 'filename|sha3-384', 'filename|sha3-512', 'filename|authentihash', 'filename|vhash', 'filename|ssdeep', 'filename|tlsh', 'filename|imphash', 'filename|pehash', 'malware-sample', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'x509-fingerprint-md5'],
        'network' => ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'mac-address', 'mac-eui-64', 'hostname', 'hostname|port', 'domain', 'domain|ip', 'email-dst', 'url', 'uri', 'user-agent', 'http-method', 'AS', 'snort', 'bro', 'zeek',  'pattern-in-traffic', 'x509-fingerprint-md5', 'x509-fingerprint-sha1', 'x509-fingerprint-sha256', 'ja3-fingerprint-md5', 'jarm-fingerprint', 'favicon-mmh3', 'hassh-md5', 'hasshserver-md5', 'community-id'],
        'financial' => ['btc', 'xmr', 'iban', 'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn', 'phone-number']
    ];
}
