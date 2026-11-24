<?php
require_once __DIR__ . '/../Lib/Tools/StixImportOptions.php';

use PHPUnit\Framework\TestCase;

if (!function_exists('__')) {
    // Fake translation function
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}

class StixImportOptionsTest extends TestCase
{
    private const BUNDLE = [
        'type' => 'bundle',
        'id' => 'bundle--0c6dcb4a-1b04-4c3d-9e2b-9d8f4a7a7f10',
        'objects' => [
            [
                'type' => 'report',
                'id' => 'report--5b0f0d4e-3c6a-4f5e-8f4b-2d3c1a0b9e8d',
                'name' => 'Example report',
            ],
        ],
    ];

    private const STIX1 =
        '<stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1"/>';

    private const DEFAULTS = [
        'publish' => false,
        'distribution' => 1,
        'sharing_group_id' => null,
        'original_file' => true,
        'force_contextual_data' => true,
        'galaxies_as_tags' => false,
        'cluster_distribution' => 1,
        'cluster_sharing_group_id' => null,
        'debug' => false,
    ];

    private function importOptions($isSiteAdmin = false, $default = 1)
    {
        return new StixImportOptions(
            $isSiteAdmin,
            [0, 1, 2, 3, 4],
            4,
            [7, 12],
            $default
        );
    }

    private function rest(
        $data,
        $rawBody,
        array $named = [],
        array $query = [],
        array $positional = [],
        $isSiteAdmin = false
    ) {
        return $this->importOptions($isSiteAdmin)
            ->fromRest($data, $rawBody, $positional, $named, $query);
    }

    private function restOptions(array $named, $isSiteAdmin = false)
    {
        $rawBody = json_encode(self::BUNDLE);
        return $this->rest(
            self::BUNDLE,
            $rawBody,
            $named,
            [],
            [],
            $isSiteAdmin
        )[1];
    }

    private function envelope(array $options)
    {
        return $this->rest(['stix' => self::BUNDLE] + $options, 'body')[1];
    }

    private function assertRejected(callable $call, $message)
    {
        try {
            $call();
        } catch (InvalidArgumentException $e) {
            $this->assertStringContainsString($message, $e->getMessage());
            return;
        }
        $this->fail('Expected the import options to be rejected: ' . $message);
    }

    public function testRawDocumentIsPassedAsSentWithDefaultOptions()
    {
        $rawBody = "{\"type\": \"bundle\", \"id\": \"bundle--0c6d\", "
            . "\"publish\": true}\n";
        $data = [
            'type' => 'bundle',
            'id' => 'bundle--0c6d',
            'publish' => true,
        ];

        [$document, $options] = $this->rest($data, $rawBody);

        $this->assertSame($rawBody, $document);
        $this->assertSame(self::DEFAULTS, $options);
    }

    public function testRawStix1DocumentIsPassedAsSent()
    {
        $data = ['STIX_Package' => []];

        [$document, $options] = $this->rest($data, self::STIX1);

        $this->assertSame(self::STIX1, $document);
        $this->assertSame(self::DEFAULTS, $options);
    }

    public function testEnvelopeObjectIsReencodedWithoutItsOptions()
    {
        $data = ['stix' => self::BUNDLE, 'distribution' => 2, 'publish' => true];

        [$document, $options] = $this->rest($data, 'body');

        $this->assertSame(self::BUNDLE, json_decode($document, true));
        $this->assertSame(2, $options['distribution']);
        $this->assertTrue($options['publish']);
    }

    public function testEnvelopeInsideRequestWrapper()
    {
        $data = [
            'request' => ['stix' => self::BUNDLE, 'galaxies_as_tags' => 1],
        ];

        [$document, $options] = $this->rest($data, 'body');

        $this->assertSame(self::BUNDLE, json_decode($document, true));
        $this->assertTrue($options['galaxies_as_tags']);
    }

    public function testEnvelopeStringIsPassedAsSent()
    {
        $data = ['stix' => self::STIX1, 'original_file' => false];

        [$document, $options] = $this->rest($data, 'body');

        $this->assertSame(self::STIX1, $document);
        $this->assertFalse($options['original_file']);
    }

    public function testEmptyOrMissingDocumentIsRejected()
    {
        $message = 'The STIX document is empty or missing.';
        $this->assertRejected(function () {
            $this->rest(null, '');
        }, $message);
        $this->assertRejected(function () {
            $this->rest([], " \n");
        }, $message);
        foreach (['', '  ', [], null, 42] as $stix) {
            $this->assertRejected(function () use ($stix) {
                $this->rest(['stix' => $stix], 'body');
            }, $message);
        }
    }

    public function testMultipartUploadIsRejected()
    {
        $upload = [
            'name' => 'bundle.json',
            'type' => 'application/json',
            'tmp_name' => '/tmp/phpA1b2C3',
            'error' => 0,
            'size' => 512,
        ];

        $this->assertRejected(function () use ($upload) {
            $this->rest(['stix' => $upload, 'publish' => '1'], '');
        }, 'The STIX document is empty or missing.');
    }

    public function testUrlOverridesTheEnvelopeAndQueryOverridesNamed()
    {
        $data = [
            'stix' => self::BUNDLE,
            'distribution' => 0,
            'publish' => true,
            'galaxies_as_tags' => true,
        ];
        $named = ['distribution' => '1', 'publish' => '0'];
        $query = ['distribution' => '2'];

        $options = $this->rest($data, 'body', $named, $query)[1];

        $this->assertSame(2, $options['distribution']);
        $this->assertFalse($options['publish']);
        $this->assertTrue($options['galaxies_as_tags']);
    }

    public function testRawDocumentTakesOptionsFromNamedAndQuery()
    {
        $rawBody = json_encode(self::BUNDLE);
        $named = ['publish' => '1', 'cluster_distribution' => '3'];
        $query = ['force_contextual_data' => 'false'];

        $options = $this->rest(self::BUNDLE, $rawBody, $named, $query)[1];

        $this->assertTrue($options['publish']);
        $this->assertSame(3, $options['cluster_distribution']);
        $this->assertFalse($options['force_contextual_data']);
    }

    public function testPathFlagsOverrideTheBodyButNotNamedParams()
    {
        $rawBody = json_encode(self::BUNDLE);
        $positional = ['1', '0', '1', '1'];

        $options = $this->rest(self::BUNDLE, $rawBody, [], [], $positional, true)[1];
        $this->assertTrue($options['publish']);
        $this->assertFalse($options['force_contextual_data']);
        $this->assertTrue($options['galaxies_as_tags']);
        $this->assertTrue($options['debug']);

        $data = ['stix' => self::BUNDLE, 'publish' => false];
        $named = ['force_contextual_data' => '1'];
        $options = $this->rest($data, 'body', $named, [], ['1', '0'])[1];
        $this->assertTrue($options['publish']);
        $this->assertTrue($options['force_contextual_data']);
    }

    public function testBooleansAcceptOnlyOneZeroTrueAndFalse()
    {
        $accepted = [
            [true, true], ['1', true], [1, true],
            ['true', true], ['TRUE', true], ['True', true],
            [false, false], ['0', false], [0, false],
            ['false', false], ['FALSE', false],
        ];
        foreach ($accepted as [$value, $expected]) {
            $options = $this->envelope(['publish' => $value]);
            $this->assertSame(
                $expected,
                $options['publish'],
                var_export($value, true)
            );
        }

        $rejected = ['yes', 'no', 'on', 'off', '2', 2, 1.0, 'abc', [1], ''];
        foreach ($rejected as $value) {
            $this->assertRejected(function () use ($value) {
                $this->envelope(['publish' => $value]);
            }, 'publish');
        }
    }

    public function testNullFallsBackToTheDefault()
    {
        $options = $this->envelope([
            'publish' => null,
            'distribution' => null,
            'force_contextual_data' => null,
        ]);

        $this->assertSame(self::DEFAULTS, $options);
    }

    public function testIntegersMustBeNumeric()
    {
        $options = $this->restOptions(['distribution' => '2']);
        $this->assertSame(2, $options['distribution']);

        foreach (['abc', '1.5', '-1', '1 ', '', 1.5, true] as $value) {
            $this->assertRejected(function () use ($value) {
                $this->restOptions(['distribution' => $value]);
            }, 'distribution');
        }
        $this->assertRejected(function () {
            $this->restOptions([
                'distribution' => '1',
                'sharing_group_id' => 'abc',
            ]);
        }, 'sharing_group_id');
    }

    public function testUnknownDistributionLevelsAreRejected()
    {
        $this->assertRejected(function () {
            $this->restOptions(['distribution' => '5']);
        }, 'Wrong distribution level');
        $this->assertRejected(function () {
            $this->restOptions(['cluster_distribution' => '5']);
        }, 'Wrong cluster distribution level');
    }

    public function testDistributionLevelsAreTheInjectedOnes()
    {
        $importOptions = new StixImportOptions(false, [0, 1, 4], 4, [7, 12], 1);
        $rawBody = json_encode(self::BUNDLE);

        $this->assertRejected(function () use ($importOptions, $rawBody) {
            $importOptions->fromRest(
                self::BUNDLE,
                $rawBody,
                [],
                ['distribution' => '2'],
                []
            );
        }, 'Wrong distribution level');
    }

    public function testSharingGroupDistributionNeedsAnAuthorisedSharingGroup()
    {
        $this->assertRejected(function () {
            $this->restOptions(['distribution' => '4']);
        }, 'The sharing group id is needed');
        $this->assertRejected(function () {
            $this->restOptions([
                'distribution' => '4',
                'sharing_group_id' => '9',
            ]);
        }, 'Please select a valid sharing group id.');

        $options = $this->restOptions([
            'distribution' => '4',
            'sharing_group_id' => '12',
        ]);
        $this->assertSame(4, $options['distribution']);
        $this->assertSame(12, $options['sharing_group_id']);

        $options = $this->restOptions([
            'distribution' => '2',
            'sharing_group_id' => '9',
        ]);
        $this->assertNull($options['sharing_group_id']);
    }

    public function testClusterSharingGroupDistributionNeedsAnAuthorisedSharingGroup()
    {
        $this->assertRejected(function () {
            $this->restOptions(['cluster_distribution' => '4']);
        }, 'The cluster sharing group id is needed');
        $this->assertRejected(function () {
            $this->restOptions([
                'cluster_distribution' => '4',
                'cluster_sharing_group_id' => '9',
            ]);
        }, 'Please select a valid cluster sharing group id.');

        $options = $this->restOptions([
            'cluster_distribution' => '4',
            'cluster_sharing_group_id' => '7',
        ]);
        $this->assertSame(4, $options['cluster_distribution']);
        $this->assertSame(7, $options['cluster_sharing_group_id']);
        $this->assertNull($options['sharing_group_id']);
    }

    public function testDebugIsHonouredForSiteAdminsOnly()
    {
        $this->assertTrue($this->restOptions(['debug' => '1'], true)['debug']);
        $this->assertTrue(
            $this->restOptions(['debugging' => '1'], true)['debug']
        );
        $this->assertFalse(
            $this->restOptions(['debug' => '0', 'debugging' => '1'], true)['debug']
        );

        $this->assertFalse($this->restOptions(['debug' => '1'])['debug']);
        $this->assertFalse(
            $this->restOptions(['debugging' => 'garbage'])['debug']
        );
    }

    public function testClusterDistributionDefaultsToTheInstanceDefault()
    {
        $importOptions = $this->importOptions(false, 3);

        $rawBody = json_encode(self::BUNDLE);
        $options = $importOptions->fromRest(self::BUNDLE, $rawBody, [], [], []);
        $this->assertSame(3, $options[1]['distribution']);
        $this->assertSame(3, $options[1]['cluster_distribution']);

        $options = $importOptions->fromForm([
            'distribution' => '0',
            'publish' => '0',
            'original_file' => '1',
        ]);
        $this->assertSame(0, $options['distribution']);
        $this->assertSame(3, $options['cluster_distribution']);
    }

    public function testUnknownKeysAreIgnored()
    {
        $data = [
            'stix' => self::BUNDLE,
            'single_event' => false,
            'title' => 'Imported',
        ];
        $named = ['producer' => 'ACME'];
        $query = ['url' => 'events/upload_stix/2'];

        $options = $this->rest($data, 'body', $named, $query)[1];

        $this->assertSame(self::DEFAULTS, $options);
    }

    public function testFormFieldsAreValidatedTheSameWay()
    {
        $form = [
            'stix' => ['name' => 'report.json', 'size' => 42],
            'distribution' => '4',
            'sharing_group_id' => '7',
            'publish' => '1',
            'original_file' => '0',
            'force_contextual_data' => '0',
            'galaxies_handling' => '1',
            'cluster_distribution' => '2',
            'cluster_sharing_group_id' => '',
            'debug' => '1',
        ];

        $options = $this->importOptions(true)->fromForm($form);

        $this->assertSame([
            'publish' => true,
            'distribution' => 4,
            'sharing_group_id' => 7,
            'original_file' => false,
            'force_contextual_data' => false,
            'galaxies_as_tags' => true,
            'cluster_distribution' => 2,
            'cluster_sharing_group_id' => null,
            'debug' => true,
        ], $options);

        $this->assertFalse($this->importOptions()->fromForm($form)['debug']);

        $this->assertRejected(function () use ($form) {
            $this->importOptions()->fromForm(['sharing_group_id' => ''] + $form);
        }, 'The sharing group id is needed');
        $this->assertRejected(function () use ($form) {
            $this->importOptions()->fromForm(['sharing_group_id' => '9'] + $form);
        }, 'Please select a valid sharing group id.');
    }

    public function testEmptyFormFieldsFallBackToTheDefault()
    {
        $options = $this->importOptions()->fromForm([
            'publish' => '',
            'distribution' => '',
            'debug' => '',
        ]);

        $this->assertSame(self::DEFAULTS, $options);
    }
}
