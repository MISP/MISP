<?php
require_once __DIR__ . '/../Lib/Tools/JSONConverterTool.php';

use PHPUnit\Framework\TestCase;

class JSONConverterToolTest extends TestCase
{
    public function testCheckJsonIsValid(): void
    {
        $attribute = ['id' => 1, 'event_id' => 2, 'type' => 'ip-src', 'value' => '1.1.1.1'];
        $event = ['Event' => ['id' => 2, 'info' => 'Test event']];
        for ($i = 0; $i < 200; $i++) {
            $event['Attribute'][] = $attribute;
        }
        $this->check($event);
    }

    public function testCheckJsonIsValidWithError(): void
    {
        $attribute = ['id' => 1, 'event_id' => 2, 'type' => 'ip-src', 'value' => '1.1.1.1'];
        $event = ['Event' => ['id' => 2, 'info' => 'Test event'], 'errors' => 'chyba'];
        for ($i = 0; $i < 200; $i++) {
            $event['Attribute'][] = $attribute;
        }
        $this->check($event);
    }

    public function testCheckJsonIsValidSmall(): void
    {
        $attribute = ['id' => 1, 'event_id' => 2, 'type' => 'ip-src', 'value' => '1.1.1.1'];
        $event = ['Event' => ['id' => 2, 'info' => 'Test event'], 'errors' => 'chyba'];
        for ($i = 0; $i < 5; $i++) {
            $event['Attribute'][] = $attribute;
        }
        $this->check($event);
    }

    private function check(array $event): void
    {
        $complexTypeTool = new JSONConverterTool();
        $json = '';
        foreach ($complexTypeTool->streamConvert($event) as $part) {
            $json .= $part;
        }
        if (defined('JSON_THROW_ON_ERROR')) {
            json_decode($json, true, 512, JSON_THROW_ON_ERROR);
            $this->assertTrue(true);
        } else {
            $this->assertNotNull(json_decode($json));
        }
    }
}
