<?php
/** Run with app/Vendor/bin/phpunit app/Test/PersonalModuleApiKeysTest.php. No DB or module service needed. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class PersonalModuleApiKeysTest extends TestCase
{
    private $module;
    private $listing = ['name' => 'virustotal', 'meta' => [
        'module-type' => ['expansion'], 'config' => ['apikey', 'url', 'limit'],
    ], 'mispattributes' => ['input' => ['sha256']]];

    protected function setUp(): void
    {
        // Keep framework stubs and production classes out of PHPUnit discovery.
        require_once __DIR__ . '/PersonalModuleApiKeysStubs.php';
        Configure::write('MISP.disableUserSelfManagement', false);
        Configure::write('Security.encryption_key', null);
        $this->module = new PersonalKeysTestModule();
        $this->module->settings = [
            'Plugin.Enrichment_virustotal_apikey' => 'instance-key',
            'Plugin.Enrichment_virustotal_url' => 'https://configured.example',
            'Plugin.Enrichment_virustotal_limit' => 10,
            'Plugin.Export_virustotal_apikey' => 'export-key',
        ];
        $this->module->credentials = [
            1 => ['Enrichment' => ['virustotal' => ['apikey' => 'alice-key']]],
            2 => ['Enrichment' => ['virustotal' => ['apikey' => 'bob-key']]],
        ];
    }

    public function testPersonalKeysAreIsolatedByUserFamilyAndModule()
    {
        $this->assertSame('alice-key', $this->config(1)['apikey']);
        $this->assertSame('bob-key', $this->config(2)['apikey']);
        $this->assertSame('instance-key', $this->config(3)['apikey']);
        $this->assertSame('alice-key', $this->config(1)['apikey']);
        $this->assertSame('export-key', $this->module->getModuleConfig($this->listing, 'Export', ['id' => 1])['apikey']);
        $other = $this->listing;
        $other['name'] = 'other';
        $this->assertNull($this->module->getModuleConfig($other, 'Enrichment', ['id' => 1])['apikey']);
        $this->assertSame('instance-key', $this->module->settings['Plugin.Enrichment_virustotal_apikey']);
    }

    public function testBlankAndNullCredentialsUseInstanceDefaultsButZeroIsAKey()
    {
        foreach (['', null] as $value) {
            $this->module->credentials[1]['Enrichment']['virustotal']['apikey'] = $value;
            $this->assertSame('instance-key', $this->config(1)['apikey']);
        }
        $this->module->credentials[1]['Enrichment']['virustotal']['apikey'] = '0';
        $this->assertSame('0', $this->config(1)['apikey']);
    }

    public function testEndpointControlsAndUndeclaredCredentialsCannotBeOverridden()
    {
        $this->module->credentials[1]['Enrichment']['virustotal'] += [
            'url' => 'https://untrusted.example', 'limit' => 999, 'enabled' => true,
            'restrict' => 2, 'unused_api_key' => 'never-send',
        ];
        $this->assertSame(['apikey' => 'alice-key', 'url' => 'https://configured.example', 'limit' => 10], $this->config(1));
    }

    public function testStructuredModuleConfigDeclarationsAreSupported()
    {
        $module = ['name' => 'virustotal', 'meta' => ['config' => [
            'apikey' => ['type' => 'string'], 'url' => 'Service URL', ['name' => 'limit', 'type' => 'numeric'],
        ]]];
        $this->assertSame($this->config(1), $this->module->getModuleConfig($module, 'Enrichment', ['id' => 1]));
    }

    public function testNoAmbientUserOrLookupForModulesWithoutConfig()
    {
        $this->assertSame('instance-key', $this->module->getModuleConfig($this->listing, 'Enrichment', [])['apikey']);
        $this->assertSame([], $this->module->getModuleConfig(['name' => 'empty'], 'Enrichment', ['id' => 1]));
        $this->assertSame([], $this->module->lookups);
    }

    public function testPersonalKeyDoesNotEnableOrUnrestrictAModule()
    {
        $this->module->listings = [$this->listing];
        Configure::write('Plugin.Enrichment_virustotal_enabled', false);
        $user = ['id' => 1, 'org_id' => 1, 'Role' => ['perm_site_admin' => false]];
        $this->assertSame([], $this->module->getEnabledModules($user));
        Configure::write('Plugin.Enrichment_virustotal_enabled', true);
        Configure::write('Plugin.Enrichment_virustotal_restrict', 2);
        $this->assertSame([], $this->module->getEnabledModules($user));
        Configure::write('Plugin.Enrichment_virustotal_restrict', null);
        $listing = $this->module->getEnabledModules($user);
        $this->assertSame('virustotal', $listing['modules'][0]['name']);
        $this->assertArrayNotHasKey('config', $listing['modules'][0]);
    }

    public function testCredentialValidationAcceptsArraysAndJson()
    {
        $value = ['Enrichment' => ['virustotal' => ['apikey' => 'my-key', 'username' => 'alice']]];
        $this->assertTrue(UserSetting::validate_module_api_keys($value, []));
        $this->assertTrue(UserSetting::validate_module_api_keys(json_encode($value), []));
        $this->assertTrue(UserSetting::validate_module_api_keys('{}', []));
        $this->assertTrue(UserSetting::validate_module_api_keys(['Import' => ['test' => ['api_key' => null]]], []));
        foreach (['apikey', 'api_key', 'authkey', 'auth_key', 'api_token', 'virustotal_apikey', 'client_secret'] as $name) {
            $this->assertTrue(Module::isPersonalCredential($name));
        }
    }

    public function testInvalidCredentialsAndControlsAreRejected()
    {
        foreach (['invalid-json', 'null', 1, ['Action' => []], ['Enrichment' => 'bad'],
            ['Enrichment' => ['bad.module' => []]], ['Enrichment' => ['module' => 'bad']]] as $value) {
            $this->assertFalse(UserSetting::validate_module_api_keys($value, []));
        }
        foreach (['url', 'api_url', 'enabled', 'restrict', 'execution_timeout', 'timeout', 'apikey_url'] as $name) {
            $this->assertFalse(UserSetting::validate_module_api_keys(['Enrichment' => ['test' => [$name => 'bad']]], []));
        }
        foreach ([true, 42, [], '*****'] as $value) {
            $this->assertFalse(UserSetting::validate_module_api_keys(['Export' => ['test' => ['apikey' => $value]]], []));
        }
    }

    public function testStorageRoundTripWithAndWithoutEncryptionAndRedactedReads()
    {
        foreach ([null, str_repeat('K', 32)] as $key) {
            Configure::write('Security.encryption_key', $key);
            $setting = new PersonalKeysTestSetting();
            $setting->data = ['UserSetting' => ['setting' => 'module_api_keys', 'value' => $this->module->credentials[1]]];
            $this->assertTrue($setting->beforeValidate());
            $this->assertTrue($setting->beforeSave());
            $raw = $setting->data['UserSetting']['value'];
            $this->assertTrue(JsonTool::isValid($raw));
            if ($key !== null) {
                $this->assertStringNotContainsString('alice-key', $raw);
            }
            $setting->rows[1] = ['UserSetting' => ['setting' => 'module_api_keys', 'value' => $raw]];
            $this->assertSame($this->module->credentials[1], $setting->getModuleApiKeys(1));
            $this->assertSame([], $setting->getModuleApiKeys(2));
            $this->assertFalse($setting->queries[0]['callbacks']);
            $this->assertSame(1, $setting->queries[0]['conditions']['UserSetting.user_id']);
            $this->assertSame('*****', $setting->afterFind([$setting->rows[1]])[0]['UserSetting']['value']);
            $this->assertSame('*****', $setting->afterFind([$setting->rows[1]['UserSetting']], false)[0]['value']);
            $this->assertSame('*****', $setting->afterFind($setting->rows[1]['UserSetting'], false)['value']);
        }
    }

    public function testWrongEncryptionKeyFailsInsteadOfFallingBackToInstanceCredentials()
    {
        $setting = new PersonalKeysTestSetting();
        Configure::write('Security.encryption_key', str_repeat('A', 32));
        $setting->data = ['UserSetting' => ['setting' => 'module_api_keys', 'value' => $this->module->credentials[1]]];
        $setting->beforeValidate();
        $setting->beforeSave();
        $setting->rows[1] = $setting->data;
        Configure::write('Security.encryption_key', str_repeat('B', 32));
        $this->expectException(Exception::class);
        $setting->getModuleApiKeys(1);
    }

    public function testKeyRotationEncryptsReencryptsAndDecryptsExistingCredentials()
    {
        $setting = new PersonalKeysTestSetting();
        $setting->rows[1] = ['UserSetting' => ['id' => 10, 'value' => JsonTool::encode($this->module->credentials[1])]];
        $old = null;
        foreach ([str_repeat('A', 32), str_repeat('B', 32), null] as $new) {
            $setting->reencryptModuleApiKeys($old, $new);
            Configure::write('Security.encryption_key', $new);
            $this->assertSame($this->module->credentials[1], $setting->getModuleApiKeys(1));
            if ($new !== null) {
                $this->assertStringNotContainsString('alice-key', $setting->rows[1]['UserSetting']['value']);
            }
            $old = $new;
        }
        $this->assertCount(3, $setting->updates);
        $this->assertStringContainsString('alice-key', $setting->rows[1]['UserSetting']['value']);
    }

    public function testOnlyOwnerCanReadOrDeleteThePersonalSetting()
    {
        $setting = new PersonalKeysTestSetting();
        $row = ['UserSetting' => ['setting' => 'module_api_keys', 'user_id' => '1']];
        $this->assertTrue($setting->checkAccess(['id' => 1], $row));
        $this->assertFalse($setting->checkAccess(['id' => 2, 'Role' => ['perm_site_admin' => true]], $row));
        Configure::write('MISP.disableUserSelfManagement', true);
        $this->assertFalse($setting->checkAccess(['id' => 1], $row));
    }

    public function testAdminCannotWriteAnotherUsersPersonalCredentials()
    {
        $setting = new PersonalKeysTestSetting();
        $setting->User = new class {
            public function find($type, $options) { return ['User' => ['org_id' => 1]]; }
        };
        $this->expectException(MethodNotAllowedException::class);
        $setting->setSetting(['id' => 2, 'Role' => ['perm_site_admin' => true]], [
            'UserSetting' => ['user_id' => 1, 'setting' => 'module_api_keys', 'value' => $this->module->credentials[1]],
        ]);
    }

    public function testOwnerCanWriteAndSelfManagementStillApplies()
    {
        $setting = new PersonalKeysTestSetting();
        $user = ['id' => 1, 'Role' => []];
        $data = ['UserSetting' => ['setting' => 'module_api_keys', 'value' => $this->module->credentials[1]]];
        $this->assertTrue($setting->setSetting($user, $data));
        $this->assertSame(1, $setting->saved['userId']);
        Configure::write('MISP.disableUserSelfManagement', true);
        $this->expectException(MethodNotAllowedException::class);
        $setting->setSetting($user, $data);
    }

    public function testBothAuditEnginesHideOldAndNewCredentialValues()
    {
        $model = (new ReflectionClass(PersonalKeysLogModel::class))->newInstanceWithoutConstructor();
        $model->data = ['UserSetting' => ['id' => 1, 'setting' => 'module_api_keys', 'value' => 'new-secret']];
        $old = ['UserSetting' => ['id' => 1, 'setting' => 'module_api_keys', 'value' => 'old-secret']];
        $audit = (new ReflectionClass(AuditLogBehavior::class))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod(AuditLogBehavior::class, 'changedFields');
        $method->setAccessible(true);
        $changes = $method->invoke($audit, $model, $old);
        $this->assertSame(['*****', '*****'], $changes['value']);
        // Deletion is logged from the current row, without an old row.
        $this->assertSame('*****', $method->invoke($audit, $model, null)['value']);

        $legacy = (new ReflectionClass(PersonalKeysLegacyLogger::class))->newInstanceWithoutConstructor();
        $legacy->prepare($old);
        $legacy->afterSave($model, false);
        $this->assertStringContainsString('*****', $legacy->captured['Log']['change']);
        $this->assertStringNotContainsString('old-secret', $legacy->captured['Log']['change']);
        $this->assertStringNotContainsString('new-secret', $legacy->captured['Log']['change']);
    }

    public function testAttributeEnrichmentSendsTheExecutionUsersCredentials()
    {
        $module = new PersonalKeysEnrichmentModule();
        $module->settings = $this->module->settings;
        $module->credentials = $this->module->credentials;
        $module->listings = [$this->listing];
        ClassRegistry::$instances['Module'] = $module;
        Configure::write('Plugin.Enrichment_virustotal_enabled', true);
        Configure::write('Plugin.Enrichment_virustotal_apikey', 'instance-key');
        Configure::write('MISP.background_jobs', false);
        $attribute = new PersonalKeysTestAttribute();
        $attribute->Event = new class {
            public function find($type, $options) { return ['Event' => ['id' => 7]]; }
            public function handleModuleResult($result, $eventId) { return []; }
        };
        foreach ([1 => 'alice-key', 2 => 'bob-key', 3 => 'instance-key'] as $userId => $expected) {
            $params = ['user' => ['id' => $userId, 'org_id' => 1, 'Role' => ['perm_site_admin' => false]], 'id' => 42, 'modules' => ['virustotal']];
            // The synchronous router and the background job both call enrichment().
            $attribute->enrichmentRouter($params);
            $this->assertSame($expected, end($module->requests)['config']['apikey']);
            $this->assertSame(0, $attribute->enrichment($params));
            $this->assertSame($expected, end($module->requests)['config']['apikey']);
        }
        $this->assertCount(6, $module->requests);
        Configure::write('Plugin.Enrichment_virustotal_enabled', false);
        $attribute->enrichment($params);
        $this->assertCount(6, $module->requests);
    }

    public function testCliRotationKeepsPersonalCredentialsReadableWithTheNewKey()
    {
        [$shell, $setting, $context] = $this->rotationHarness();
        foreach ([str_repeat('A', 32), str_repeat('B', 32)] as $newKey) {
            $context->steps = [];
            // Omit --old to exercise the command's configured-key fallback.
            $shell->params = ['new' => $newKey];
            $shell->reencrypt();
            $this->assertSame(['begin', 'system', 'server', 'cerebrate', 'personal', 'save-key', 'commit'], $context->steps);
            $this->assertSame($newKey, Configure::read('Security.encryption_key'));
            $this->assertSame($this->module->credentials[1], $setting->getModuleApiKeys(1));
            $this->assertStringNotContainsString('alice-key', $setting->rows[1]['UserSetting']['value']);
        }
    }

    public function testCliRotationRollsBackWithoutSavingNewKeyWhenPersonalRotationFails()
    {
        [$shell, $setting, $context] = $this->rotationHarness();
        $setting->failUpdate = true;
        $shell->params = ['new' => str_repeat('A', 32)];
        try {
            $shell->reencrypt();
            $this->fail('The failed personal credential update must abort key rotation.');
        } catch (RuntimeException $e) {
            $this->assertSame('Could not rotate personal module credentials.', $e->getMessage());
        }
        $this->assertSame(['begin', 'system', 'server', 'cerebrate', 'personal', 'rollback'], $context->steps);
        $this->assertNull(Configure::read('Security.encryption_key'));
        $this->assertSame($this->module->credentials[1], $setting->getModuleApiKeys(1));
    }

    private function rotationHarness()
    {
        $context = new PersonalKeysRotationContext();
        $setting = new PersonalKeysRotationSetting();
        $setting->context = $context;
        $setting->rows[1] = ['UserSetting' => ['id' => 10, 'value' => JsonTool::encode($this->module->credentials[1])]];
        ClassRegistry::$instances = [
            'SystemSetting' => new PersonalKeysRotationParticipant($context, 'system'),
            'Cerebrate' => new PersonalKeysRotationParticipant($context, 'cerebrate'),
            'UserSetting' => $setting,
        ];
        $shell = new PersonalKeysTestAdminShell();
        $shell->Server = new PersonalKeysRotationServer($context);
        return [$shell, $setting, $context];
    }

    private function config($userId)
    {
        return $this->module->getModuleConfig($this->listing, 'Enrichment', ['id' => $userId]);
    }
}
