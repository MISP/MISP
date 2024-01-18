<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class AttributesFixture extends TestFixture
{
    public $connection = 'test';

    public function init(): void
    {
        $this->records = [];
        parent::init();
    }
}
