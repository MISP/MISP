<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\Http\Exception\NotImplementedException;
use Cake\TestSuite\Fixture\TestFixture;

class EncryptionKeysFixture extends TestFixture
{
    public $connection = 'test';

    public const ENCRYPTION_KEY_ORG_A_ID = 1;
    public const ENCRYPTION_KEY_ORG_B_ID = 2;

    public const TYPE_PGP = 'pgp';
    public const TYPE_SMIME = 'smime';

    public const KEY_TYPE_EDCH = 'EDCH';
    public const KEY_TYPE_RSA = 'RSA';
    public const KEY_TYPE_SMIME = 'S/MIME';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::ENCRYPTION_KEY_ORG_A_ID,
                'uuid' => $faker->uuid(),
                'type' => self::TYPE_PGP,
                'encryption_key' => $this->getPublicKey(self::KEY_TYPE_EDCH),
                'revoked' => false,
                'expires' => null,
                'owner_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'owner_model' => 'Organisation',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::ENCRYPTION_KEY_ORG_B_ID,
                'uuid' => $faker->uuid(),
                'type' => self::TYPE_PGP,
                'encryption_key' => $this->getPublicKey(self::KEY_TYPE_EDCH),
                'revoked' => false,
                'expires' => null,
                'owner_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'owner_model' => 'Organisation',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
        ];
        parent::init();
    }

    public static function getPublicKey(string $type): string
    {
        switch ($type) {
            case self::KEY_TYPE_EDCH:
                return <<<EOD
                -----BEGIN PGP PUBLIC KEY BLOCK-----
                Version: OpenPGP v1.0.0

                xm8EYeaEmhMFK4EEACIDAwTS1DNpEsyLo6ynsxJhe1J1k75OYGjkiYgj+4157e06
                m8uNX9TRI3XKAKUs2ecG6Iv6beXpvLHcBu/GqwYnpLigpABkhLbUob5spIg+OqNA
                l0U75pLyshmQ8DOWupjq2ZTNG2Zvb2JhciA8Zm9vYmFyQGV4YW1wbGUuY29tPsKP
                BBMTCgAXBQJh5oSaAhsvAwsJBwMVCggCHgECF4AACgkQfYJ4NsWgZlqadgF6Apv0
                S3JrJgmUejRVaMBoAlGlME6OibfAo/faYyOhO/tb0Kw8MYfrF27D+N3/TR8BAX0e
                KhJvhcoHZlcb6E+xUvAT9zYyCpX6g1s2rU9qeLJEbWeEiz7/e1diYgQ2TuuJTr/O
                UgRh5oSaEwgqhkjOPQMBBwIDBHTGkUJ9McCAGMB9/jhzJJ9arYLIdMUwHbxf68K3
                yQaiQf2F0BUciz37I2pFPBV17CJzsHdoIG4rhrU4PI+srzvCwCcEGBMKAA8FAmHm
                hJoFCQ8JnAACGy4AagkQfYJ4NsWgZlpfIAQZEwoABgUCYeaEmgAKCRC+TAWGbVzh
                xvHIAP9C6iogC55FEE8XuQ2g6dPyIyou940sLQIYKdFpG2CTnwEAvosKiPEC+bwC
                b75QibMSCGlYPOIO5WW9OqJyT4I59bwH4QF+KRv6b3wOoFz8/ptDyIbFpNSoBrDT
                9D35Gk9oVSZg9FDeQunGRt2qkvfDxBMecPWXAYDlNTFtdBUWeXeMLJlEr5YyC3SA
                RIbej4EnbpXmhdODjKLv1p5tAOw/lgEfQKzBEwbOUgRh5oSaEwgqhkjOPQMBBwID
                BO9vsx/0+act9x1hNk0LHxE/PELjL2Abn/JBjAIvGgTmiZc5Vkb2XrUYAoOhKI4G
                ab9UTnlGznER74SWWLELUt7CwCcEGBMKAA8FAmHmhJoFCQ8JnAACGy4AagkQfYJ4
                NsWgZlpfIAQZEwoABgUCYeaEmgAKCRC5+NJ8Prn4UPSRAQCH7Ek29Z9ivuvIaj6n
                2AYdgHZHBEYAg5uwSBchPRXBHwD/QxRRAyKnwdmTLJzaB7M82bHLRU5WXbEgqucv
                9HuQpkiv6wGA2NVSulEz7VxxKIcaU8xQRrStIBXqMvNo/13kdlq2YWQ6EZnG7EU7
                ExIU8Y2OkuFWAX9gLoJCjxfMuH5u27nNkztxL4SgORfCxWRg6VaVAFXX21dlQwIf
                XUzE5dzw+nOspVE=
                =WnCK
                -----END PGP PUBLIC KEY BLOCK-----
                EOD;
            default:
                throw new NotImplementedException('Unknown key type');
        }
    }

    private static function getPrivateKey(string $type): string
    {
        switch ($type) {
            case self::KEY_TYPE_EDCH:
                return <<<EOD
                -----BEGIN PGP PRIVATE KEY BLOCK-----
                Version: OpenPGP v1.0.0
        
                xcASBGHmhJoTBSuBBAAiAwME0tQzaRLMi6Osp7MSYXtSdZO+TmBo5ImII/uNee3t
                OpvLjV/U0SN1ygClLNnnBuiL+m3l6byx3AbvxqsGJ6S4oKQAZIS21KG+bKSIPjqj
                QJdFO+aS8rIZkPAzlrqY6tmU/gkDCCcuNcl1iEuoYIjwDlg5yqzxdXu9Q7V+WvBf
                OflkWwIGYLjrqcDWNZqz9v4alO8/uKPZoRyYmQx3yBxjgrNs4bjibFxc43oTlHtD
                JA7m+Ba4cWyMVFJ96TPXAvI5fAJszRtmb29iYXIgPGZvb2JhckBleGFtcGxlLmNv
                bT7CjwQTEwoAFwUCYeaEmgIbLwMLCQcDFQoIAh4BAheAAAoJEH2CeDbFoGZamnYB
                egKb9EtyayYJlHo0VWjAaAJRpTBOjom3wKP32mMjoTv7W9CsPDGH6xduw/jd/00f
                AQF9HioSb4XKB2ZXG+hPsVLwE/c2MgqV+oNbNq1PaniyRG1nhIs+/3tXYmIENk7r
                iU6/x6UEYeaEmhMIKoZIzj0DAQcCAwR0xpFCfTHAgBjAff44cySfWq2CyHTFMB28
                X+vCt8kGokH9hdAVHIs9+yNqRTwVdewic7B3aCBuK4a1ODyPrK87/gkDCCiGr5A8
                Yq+pYCpNvctmdVC3wwN+LNpiXHtkYWD37TdpwrdR0h8H/PSZFdHgkyK3tqmxPApC
                S3+s+cBzza5mTPqaq/7Cc6ck40juXNBIC8rCwCcEGBMKAA8FAmHmhJoFCQ8JnAAC
                Gy4AagkQfYJ4NsWgZlpfIAQZEwoABgUCYeaEmgAKCRC+TAWGbVzhxvHIAP9C6iog
                C55FEE8XuQ2g6dPyIyou940sLQIYKdFpG2CTnwEAvosKiPEC+bwCb75QibMSCGlY
                POIO5WW9OqJyT4I59bwH4QF+KRv6b3wOoFz8/ptDyIbFpNSoBrDT9D35Gk9oVSZg
                9FDeQunGRt2qkvfDxBMecPWXAYDlNTFtdBUWeXeMLJlEr5YyC3SARIbej4EnbpXm
                hdODjKLv1p5tAOw/lgEfQKzBEwbHpQRh5oSaEwgqhkjOPQMBBwIDBO9vsx/0+act
                9x1hNk0LHxE/PELjL2Abn/JBjAIvGgTmiZc5Vkb2XrUYAoOhKI4Gab9UTnlGznER
                74SWWLELUt7+CQMI0o+tsXn5S31gHyPTI5yRG0I7dZg4OrU+tCu11AYzC4y3aO0M
                E2tixY7BDHIgtiWkeDWo8j4f8zYhBL9x/M3mpinZ6vQEhOdED+8shBmPNMLAJwQY
                EwoADwUCYeaEmgUJDwmcAAIbLgBqCRB9gng2xaBmWl8gBBkTCgAGBQJh5oSaAAoJ
                ELn40nw+ufhQ9JEBAIfsSTb1n2K+68hqPqfYBh2AdkcERgCDm7BIFyE9FcEfAP9D
                FFEDIqfB2ZMsnNoHszzZsctFTlZdsSCq5y/0e5CmSK/rAYDY1VK6UTPtXHEohxpT
                zFBGtK0gFeoy82j/XeR2WrZhZDoRmcbsRTsTEhTxjY6S4VYBf2AugkKPF8y4fm7b
                uc2TO3EvhKA5F8LFZGDpVpUAVdfbV2VDAh9dTMTl3PD6c6ylUQ==
                =96JC
                -----END PGP PRIVATE KEY BLOCK-----
                EOD;
            default:
                throw new NotImplementedException('Unknown key type');
        }
    }
}
