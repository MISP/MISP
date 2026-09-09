<?php
/**
 * Module::queryAI() and its request builders (AI UX P1.4): the envelope of
 * PRD §3.1, the un-prefixed `params` block built from the Plugin.AI_* settings,
 * and the handling of the module's answer.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB, no socket (the app/Test
 * convention). Module.php only needs App::uses() and AppModel at load time.
 * queryAI() is driven through a subclass that records what sendRequest()
 * receives and answers with an injected response, and that reads the AI
 * settings from an injected map instead of Configure.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!class_exists('JsonTool', false)) {
    class JsonTool
    {
        public static function encode($value)
        {
            return json_encode($value);
        }
    }
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}

require_once __DIR__ . '/../Model/Module.php';

class TestableAiModule extends Module
{
    public $settings = [];
    public $response = ['results' => []];
    public $sent = null;
    /** What getModules('AI') answers: a listing, or an Exception to throw. */
    public $listing = [];

    public function aiSetting($name)
    {
        return array_key_exists($name, $this->settings) ? $this->settings[$name] : null;
    }

    public function sendRequest($uri, $timeout, $postData = null, $moduleFamily = 'Enrichment')
    {
        $this->sent = compact('uri', 'timeout', 'postData', 'moduleFamily');
        return $this->response;
    }

    public function getModules($moduleFamily = 'Enrichment', $throwException = false)
    {
        $this->sent = compact('moduleFamily', 'throwException');
        if ($this->listing instanceof Exception) {
            throw $this->listing;
        }
        return $this->listing;
    }
}

class ModuleAiRequestTest extends TestCase
{
    // ---- constants -------------------------------------------------------

    public function testParamSettingsAreTheUnprefixedModuleConfigNames()
    {
        $expected = ['openai_api_base', 'api_key', 'model_id', 'temperature', 'request_timeout', 'suggest_limit', 'suggest_min_score'];
        $this->assertSame($expected, Module::AI_PARAM_SETTINGS);
        foreach (Module::AI_PARAM_SETTINGS as $name) {
            $this->assertStringStartsNotWith('AI_', $name);
        }
        $this->assertSame('ai_connector', Module::AI_MODULE_NAME);
    }

    // ---- buildAiParams ---------------------------------------------------

    public function testParamsCarryEveryConfiguredSettingUnprefixed()
    {
        $values = [
            'openai_api_base' => 'http://llm:11434/v1',
            'api_key' => 'k',
            'model_id' => 'gemma4:12b',
            'temperature' => 0.2,
            'request_timeout' => 120,
            'suggest_limit' => 5,
            'suggest_min_score' => 0.0,
        ];
        $params = Module::buildAiParams(function ($name) use ($values) {
            return $values[$name];
        });
        $this->assertSame($values, $params);
    }

    public function testUnsetAndEmptySettingsAreLeftOut()
    {
        $params = Module::buildAiParams(function ($name) {
            $values = ['api_key' => '', 'model_id' => 'm', 'temperature' => null];
            return array_key_exists($name, $values) ? $values[$name] : null;
        });
        $this->assertSame(['model_id' => 'm'], $params);
    }

    public function testZeroIsAValue()
    {
        $params = Module::buildAiParams(function ($name) {
            return $name === 'temperature' ? 0 : ($name === 'suggest_min_score' ? '0' : null);
        });
        $this->assertSame(['temperature' => 0, 'suggest_min_score' => '0'], $params);
    }

    public function testOnlyTheDeclaredSettingsAreRead()
    {
        $asked = [];
        Module::buildAiParams(function ($name) use (&$asked) {
            $asked[] = $name;
            return null;
        });
        $this->assertSame(Module::AI_PARAM_SETTINGS, $asked);
    }

    // ---- buildAiRequest --------------------------------------------------

    public function testEnvelopeMatchesTheContract()
    {
        $data = ['Event' => ['id' => 1, 'info' => 'x']];
        $params = ['model_id' => 'm'];
        $request = Module::buildAiRequest('tag_suggest', $data, $params, '300');
        $this->assertSame([
            'module' => 'ai_connector',
            'data' => $data,
            'use_case' => 'tag_suggest',
            'params' => $params,
            'timeout' => 300,
        ], $request);
        $this->assertIsInt($request['timeout']);
    }

    public function testEveryUseCaseIsAccepted()
    {
        foreach (['summarization_on_event', 'summarization_on_eventReport', 'tag_suggest'] as $useCase) {
            $request = Module::buildAiRequest($useCase, [], [], 1);
            $this->assertSame($useCase, $request['use_case']);
        }
        $this->assertSame(['summarization_on_event', 'summarization_on_eventReport', 'tag_suggest'], Module::AI_USE_CASES);
    }

    public function testUnknownUseCaseIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        Module::buildAiRequest('summarise', [], [], 1);
    }

    // ---- queryAI ---------------------------------------------------------

    private function module(array $settings, array $response)
    {
        $module = new TestableAiModule();
        $module->settings = $settings;
        $module->response = $response;
        return $module;
    }

    public function testQueryPostsTheEnvelopeToTheAiFamily()
    {
        $module = $this->module(
            ['timeout' => 45, 'model_id' => 'm', 'api_key' => 'k', 'temperature' => 0],
            ['results' => ['Tag' => [['name' => 'tlp:amber']]]]
        );
        $results = $module->queryAI('tag_suggest', ['Event' => ['id' => 7]]);

        $this->assertSame(['Tag' => [['name' => 'tlp:amber']]], $results);
        $this->assertSame('/query', $module->sent['uri']);
        $this->assertSame('AI', $module->sent['moduleFamily']);
        $this->assertSame(45, $module->sent['timeout']);
        $this->assertSame([
            'module' => 'ai_connector',
            'data' => ['Event' => ['id' => 7]],
            'use_case' => 'tag_suggest',
            'params' => ['api_key' => 'k', 'model_id' => 'm', 'temperature' => 0],
            'timeout' => 45,
        ], $module->sent['postData']);
    }

    public function testExplicitTimeoutWinsOverTheSetting()
    {
        $module = $this->module(['timeout' => 45], ['results' => []]);
        $module->queryAI('summarization_on_event', ['Event' => []], 7);
        $this->assertSame(7, $module->sent['timeout']);
        $this->assertSame(7, $module->sent['postData']['timeout']);
    }

    public function testTimeoutFallsBackTo300WhenNothingIsConfigured()
    {
        $module = $this->module([], ['results' => []]);
        $module->queryAI('summarization_on_event', ['Event' => []]);
        $this->assertSame(300, $module->sent['timeout']);
    }

    public function testModuleErrorBecomesAnException()
    {
        $module = $this->module([], ['error' => 'model not found']);
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('model not found');
        $module->queryAI('tag_suggest', ['Event' => []]);
    }

    public function testMissingResultsIsAnEmptyArray()
    {
        $module = $this->module([], ['something' => 'else']);
        $this->assertSame([], $module->queryAI('tag_suggest', ['Event' => []]));
    }

    public function testUnreadableAnswerIsAnException()
    {
        $module = $this->module([], ['results' => []]);
        $module->response = 'not json';
        $this->expectException(Exception::class);
        $module->queryAI('tag_suggest', ['Event' => []]);
    }

    public function testUnknownUseCaseNeverReachesTheModule()
    {
        $module = $this->module([], ['results' => []]);
        try {
            $module->queryAI('bogus', ['Event' => []]);
            $this->fail('expected InvalidArgumentException');
        } catch (InvalidArgumentException $e) {
            $this->assertNull($module->sent);
        }
    }

    // ---- aiStatus --------------------------------------------------------

    private function connector($version = '1.0')
    {
        return ['name' => 'ai_connector', 'meta' => ['module-type' => ['ai'], 'version' => $version, 'description' => 'd']];
    }

    public function testStatusWhenDisabledDoesNotTouchTheServer()
    {
        $module = $this->module(['services_enable' => false, 'services_url' => 'http://127.0.0.1/', 'services_port' => 6667], []);
        $status = $module->aiStatus();
        $this->assertFalse($status['enabled']);
        $this->assertSame('http://127.0.0.1:6667', $status['server']);
        $this->assertFalse($status['reachable']);
        $this->assertFalse($status['listed']);
        $this->assertNull($module->sent);
    }

    public function testStatusUnreachableCarriesTheError()
    {
        $module = $this->module(['services_enable' => true, 'services_url' => 'http://h', 'services_port' => 1], []);
        $module->listing = new Exception('curl error 7');
        $status = $module->aiStatus();
        $this->assertTrue($status['enabled']);
        $this->assertFalse($status['reachable']);
        $this->assertSame('curl error 7', $status['error']);
        $this->assertFalse($status['listed']);
        $this->assertSame(['moduleFamily' => 'AI', 'throwException' => true], $module->sent);
    }

    public function testStatusReachableButModuleMissing()
    {
        $module = $this->module(['services_enable' => 1, 'services_url' => 'http://h', 'services_port' => 1], []);
        $module->listing = [['name' => 'other', 'meta' => ['module-type' => ['expansion']]]];
        $status = $module->aiStatus();
        $this->assertTrue($status['reachable']);
        $this->assertFalse($status['listed']);
        $this->assertNull($status['module']);
        $this->assertNull($status['error']);
    }

    public function testStatusReady()
    {
        $module = $this->module(['services_enable' => true, 'services_url' => 'http://h', 'services_port' => 1], []);
        $module->listing = [['name' => 'other', 'meta' => []], $this->connector('0.0-fake')];
        $status = $module->aiStatus();
        $this->assertTrue($status['reachable']);
        $this->assertTrue($status['listed']);
        $this->assertSame(['version' => '0.0-fake', 'description' => 'd', 'types' => ['ai']], $status['module']);
    }

    public function testStatusWithAnUnreadableListing()
    {
        $module = $this->module(['services_enable' => true, 'services_url' => 'http://h', 'services_port' => 1], []);
        $module->listing = 'Module service not reachable.';
        $status = $module->aiStatus();
        $this->assertTrue($status['reachable']);
        $this->assertFalse($status['listed']);
        $this->assertNotNull($status['error']);
    }
}
