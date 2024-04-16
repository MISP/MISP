<?php

declare(strict_types=1);

namespace App\Test\TestCase\Tool;

use App\Lib\Tools\RedisTool;
use Cake\TestSuite\TestCase;

class RedisToolTest extends TestCase
{
    public function testConnection()
    {
        $redis = RedisTool::init();
        $this->assertInstanceOf('Redis', $redis);

    }

    public function testSerializeDeserialize()
    {
        $faker = \Faker\Factory::create();
        $data = $faker->text(400);
        $serialized = RedisTool::serialize($data);
        $this->assertNotEquals($data, $serialized);
        $deserialized = RedisTool::deserialize($serialized);
        $this->assertEquals($data, $deserialized);
    }

    public function testCompressDecompress()
    {
        $faker = \Faker\Factory::create();

        $data = '';
        while (strlen($data) < RedisTool::COMPRESS_MIN_LENGTH) {
            $data .= $faker->text(400);
        }
        $compressed = RedisTool::compress($data);
        $decompressed = RedisTool::decompress($compressed);
        $this->assertEquals($data, $decompressed);
    }

}