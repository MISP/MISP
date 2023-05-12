<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\CryptographicKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddCryptographicKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cryptographic-keys/add/%s/%s';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.CryptographicKeys'
    ];

    public function testAddCryptographicKey(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf(self::ENDPOINT, 'User', 1);

        $pgp_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: OpenPGP v2.0.76\nComment: foobar\n\nxo0EZF4jyAEEAMCyxkNt4fo1FKoHs9MM0/T5GQMphmWbaBN7Rednng9WWgICQAq4\nnGn2a0uTJXH3aleej9udK10J3itT+OO8yPA2h79O/6Nfxg6rnEaYpNoEsymjDxZU\nHOBPCNzsBfjC6xwQ7LQ4gARiOmmgrej1uNZTlbs1DhlbhZ1UatfYx+A7ABEBAAHN\nFUZvbyBCYXIgPGZvb0BiYXIuY29tPsK6BBMBCgAkBQJkXiPIAhsvAwsJBwMVCggC\nHgECF4ADFgIBAhkBBQkAAAAAAAoJEDGhkzanZjD/v8AEAJKEjSAk/NWKofOdOA4S\nvMPOXehuZ8MI7yL5WOYmWSpYSZPwmexwNNgjf/tjG6NOABuxti8nHxErNVHRHl60\n5LjlQfeplwjieFoz+XXJKKFbtpqxiaadxgO+krplygnMwCQdQV9BjJ1d7J7O5TNw\n4rswxI3CWAFWf/8uLmuevkdmzo0EZF4jyAEEANhoi9s74ts3dDktzdBd7wRu5f0r\nedHOj0wS72lCxr/wmojzIU5RMYwmNmKhrzht7LgQqqdYdSoPdB3yg3/awZhfihAD\nO+ONMhwrL2E+Fr90JH4qCtn4OgcGtulrA3dE/LzpzfkKa5dazXDmYO+NaYr6WBMM\n3QljcnuWDjxWhrnXABEBAAHCwIMEGAEKAA8FAmReI8gFCQAAAAACGy4AqAkQMaGT\nNqdmMP+dIAQZAQoABgUCZF4jyAAKCRDtPILTQY19iy2bBACjRXd4LRfxNQFnU19r\nbiXyfQzFgm0cS5GfhrYPARGHDKiBuEcAXobk7nZB44zTXM4H8gqte6M+991DzclL\nX07MZkIe/XFeANgQ6ER5yiTgPBnHU4TzQUTpw/TU5siqdm9wsE8cI3r9Dv5Efw+A\n0vEyepIbakIu3wVZu9QFYyd/KjkWBACRobSygYUQN43knI83+Bo09aNTJF8eQ68k\n2zrlnpJruskhgwHjOg7WWi7Q+RCsTKrx735fnf+LlMa5DtXpRAAW2/c8pstjeTnb\nMfGlWjOaR/g9OsQMWn0gt+dQoEsMJPHkzng9d3dMQBcxHiWyZd32et1uV3T9sswY\n2uYWMNvOP86NBGReI8gBBADIY6kuza0SKcUQ5rUZMUNs0iiM4ReleVO6W4HXG8aR\n9jfj2OSaafw+UeuKh73yH0e+0vB+0NP6XdLam/Ne5+vZUXtlW03F/Nd8j2xZF7iJ\nUBw1kCFvLEAF63qvyZXGLOdFe4GFginlvS+2f1gV8BCn15k1hqPxMd38ZvH6QXUr\nEQARAQABwsCDBBgBCgAPBQJkXiPIBQkAAAAAAhsuAKgJEDGhkzanZjD/nSAEGQEK\nAAYFAmReI8gACgkQKd6KLuhHZfkYWwQAlaXK1f2m40L6F4jsA+LNL89PzNPlE3il\n36dQ3kDA4enlKSUjNT9Zbkgl+QQOSnO3u75HH09ZEU293qanzDO790dLHou0Y9cF\nJD0UU6yIqpl+Swsm85F5q5HiRqrR0Lr8iaMbaMcu3zrOE01g6byKrJbtji7TeSNo\n0SEvX6nBkAtBggP8D82Qcx5hZafofB8zT/iBYx5kLKVJKUbRD5VDfZid9KR1ERHc\ndNXLaD1yEAWLGYd6UnExlw5AulW8ejdyZNq7HRmJmaXMX2RhjhHZWz3NzzBoxM4o\nNm+/4L6MlU1uiDmrOZ5tQu3LxNxn3oqWKUH457uDiKCn4WTO9yET00kFvOE=\n=DCP7\n-----END PGP PUBLIC KEY BLOCK-----\n";

        $this->post(
            $url,
            [
                'type' => 'pgp',
                'key_data' => $pgp_key
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('CryptographicKeys', ['key_data' => $pgp_key]);
    }
}
