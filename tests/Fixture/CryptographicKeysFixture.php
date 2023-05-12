<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class CryptographicKeysFixture extends TestFixture
{
    public $connection = 'test';

    public const CRYPTOGRAPHIC_KEY_REGULAR_USER_ID = 1000;
    public const CRYPTOGRAPHIC_KEY_REGULAR_USER_UUID = 'a2c4d61a-b06e-4390-b09d-a64d54225565';

    public function init(): void
    {
        $faker = \Faker\Factory::create();
        $key_data = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP v2.0.76\nComment: foobar\n\nxo0EZF484AEEAMYH6aqsoXKOaJ61efIneGc789aOm78ITjiwO0ZzuofLRu3Zdgbq\nKFFpSgubBGIHeZw2wz76vlU5bATJn/pE8bBHBT03HN+P3lOB/mIOcJzza95y8YV4\n3qOUF04bw4gZFBzSmwMGsQr1u5xA90aaYmD2t9GSHHXOLKXNYSaFCxtTABEBAAHN\nFFVzZXIgPHVzZXJAbWlzcC5jb20+wroEEwEKACQFAmRePOACGy8DCwkHAxUKCAIe\nAQIXgAMWAgECGQEFCQAAAAAACgkQxtKFjHNXIf4XYAQAxQp/ZLnVpPKaj3kOk0b1\nbtNtPTJQOY3k6B9OYWCb3rr1/uziTasr/Z7dcBbr5/80EVjR9EJ2CnRV1xpDWKuu\nyI6QBg/MRNRtkJg1DilUVqaL5SraK8q7C+cPoO+IwvbJ+GtGu1gh60DOc7rKwYuL\nguc8GVRkWIUidauDFp98BAHOjQRkXjzgAQQA2oSVTAbctL//xwQnEVMwlAJ9uj8E\nM4eS/wUQRHXOa54ti3q0Xt23oNVEQtprBp93XtIeW2rZfVqHBIxp2RDSDZcAgwzf\nEfG6z7ykdgWnTm8NwfZRZETMcfkDA07O74Lj8PjuEj6HRr4lPSacT/aL2H7dMrDF\nC4SvdDQoN5oM5L8AEQEAAcLAgwQYAQoADwUCZF484AUJAAAAAAIbLgCoCRDG0oWM\nc1ch/p0gBBkBCgAGBQJkXjzgAAoJELsL/SDS6/ak1uYEAKoZ/hZ+1SlVcsi9Ihar\nq3P6vB7ZAXc/YmLdwXCJRoknAdGcvDsxGVu9vV74PVyU57OqEnqFiYaCYYm2LjBf\nMWODx1UL8ShCcTyLNntI58uytUE80F5qEdvTzj2qI5WuD/aZ7UHXQiE4/EPO154e\nVOGf0rnzCJF2eZEdCb8eEPRrVjED/RqVuQogoidrpJ9um2l5tfWkNjld2HMHdK1h\nl4XqF+W0sEQdM0Zlsr1JGpAIYSi0PDZLb3Q2vNAHk4dJhKgSw9P+6IRLDOUGhg1L\n1OKFM3CnCDiPRl51SuzAngvkbjwLBrCrCZ12dmsnjLNbewjf9BJxV6wxNXj2+fnA\n2E+3BHm5zo0EZF484AEEAMtGgS8KgZs4kDT/zJEiRmPIikN2E9xzufLYR94Md5jH\nqceyZN56sEBlV0kAstyiHusFR3SiQT/MUFUEnO3xlR9XNZx0ka9heT+5sbL1099f\nbbl+trJDAkWo5OuOHYNkEXRnhHOAl/DaAvgVtAhn191cdk9PqhT0qgTQCweR35qb\nABEBAAHCwIMEGAEKAA8FAmRePOAFCQAAAAACGy4AqAkQxtKFjHNXIf6dIAQZAQoA\nBgUCZF484AAKCRBHg4xdjs5JtWoVA/0fJhnCGqdDu7SAM3RlekEZa+ygBTgI5UFJ\nQC8Rtcf63dLzf5tz63CGCRBXemkpkz/AWbgxQX6BFUa8jrYMQp0ZpCZXi8x4c3d1\n5P0FrechOUbv30twv1xZmDxvvgN476PGVTGH3uDwELIa36h1VKC1rkeWHBU3p2yH\nssoA6ELxxnOiA/0YMDUvs7DZ3asWTpA7Vpee1YWlDcyudEQ9p1nmPgOFuLETLhpK\nhfvV5bgxlFgptDdtZ/Y9TioprbHcu1B5pB98cLStccpEuUn403cs3NgvHjfhdp9z\nJNSdGU4DKNkAnSipVBqGocCZFqHkXltjVY0Q49TITJ+t1NJSSGQY/wVxsw==\n=5n9/\n-----END PGP PUBLIC KEY BLOCK-----';

        $this->records = [
            [
                'id' => self::CRYPTOGRAPHIC_KEY_REGULAR_USER_ID,
                'uuid' => self::CRYPTOGRAPHIC_KEY_REGULAR_USER_UUID,
                'timestamp' => $faker->dateTime()->getTimestamp(),
                'parent_id' => UsersFixture::USER_REGULAR_USER_ID,
                'parent_type' => 'User',
                'key_data' => $key_data,
                'type' => 'pgp',
                'revoked' => 0,
                'fingerprint' => ''
            ]
        ];
        parent::init();
    }
}
