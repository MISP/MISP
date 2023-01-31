<?php

namespace MetaFieldsTypes;

use MetaFieldsTypes\IPv4Type;

class IPv6Type extends IPv4Type
{
    public const TYPE = 'ipv6';

    public function __construct()
    {
        parent::__construct();
    }

    protected function _isValidIP(string $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

}
