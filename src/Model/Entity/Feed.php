<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class Feed extends AppModel
{
    public const DEFAULT_FEED_PULL_RULES = [
        'tags' => [
            "OR" => [],
            "NOT" => [],
        ],
        'orgs' => [
            "OR" => [],
            "NOT" => [],
        ],
        'url_params' => ''
    ];

    public const SUPPORTED_URL_PARAM_FILTERS = [
        'timestamp',
        'publish_timestamp',
    ];

    public const CACHE_DIR = APP . 'tmp' . DS . 'cache' . DS . 'feeds' . DS;

    public const FEED_TYPES = array(
        'misp' => array(
            'name' => 'MISP Feed'
        ),
        'freetext' => array(
            'name' => 'Freetext Parsed Feed'
        ),
        'csv' => array(
            'name' => 'Simple CSV Parsed Feed'
        )
    );
}
