<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;

class AccessLog extends AppModel
{
    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const COMPRESS_MIN_LENGTH = 256;

    const REQUEST_TYPES = [
        0 => 'Unknown',
        1 => 'GET',
        2 => 'HEAD',
        3 => 'POST',
        4 => 'PUT',
        5 => 'DELETE',
        6 => 'OPTIONS',
        7 => 'TRACE',
        8 => 'PATCH',
    ];
}
