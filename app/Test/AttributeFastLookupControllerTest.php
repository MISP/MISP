<?php
/**
 * Exercise the real action and its JSON input callback without a database or
 * CakePHP bootstrap, following the standalone app/Test convention.
 */

use PHPUnit\Framework\TestCase;

/**
 * Load controller/framework doubles only in child processes so discovering this
 * suite cannot replace the incompatible global stubs used by neighboring tests.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class AttributeFastLookupControllerTest extends TestCase
{
    private $controller;

    protected function setUp(): void
    {
        require_once __DIR__ . '/fixtures/FastLookupControllerStubs.php';
        $this->assertTrue(method_exists(AttributesController::class, 'fastLookup'), 'The fastLookup action must exist.');
        Configure::write('MISP.fast_lookup_enabled', true);
        Configure::write('debug', 0);
        Configure::write('Security.allow_cors', false);
        $this->controller = new AttributesController();
        $this->controller->request = new FastLookupControllerRequest();
        $this->controller->response = new CakeResponse();
        $this->controller->MispAttribute = new FastLookupControllerModel();
        $this->controller->Auth = new class {
            public function user() { return ['id' => '7', 'org_id' => '3', 'Role' => ['perm_site_admin' => false]]; }
        };
        $this->controller->RestResponse = (new ReflectionClass(RestResponseComponent::class))->newInstanceWithoutConstructor();
        $this->controller->RequestHandler = new FastLookupControllerRequestHandler();
        $this->controller->Security = (object)['unlockedActions' => []];
    }

    public function testReturnsOnlyTheMappingAndForwardsTheCurrentUserAndRequest(): void
    {
        $request = ['value' => ['example.org', 'missing.example']];
        $this->controller->request->data = $request;
        $this->controller->MispAttribute->result = ['status' => 'ready', 'scope' => FastLookupConfig::scope(), 'results' => (object)['example.org' => ['event_ids' => ['2', '11']]]];
        $this->controller->RestResponse->headers = ['X-Rate-Limit-Remaining' => 4];
        $response = $this->controller->fastLookup();
        $this->assertSame(200, $response->statusCode());
        $this->assertSame('json', $response->type());
        $this->assertSame(JsonTool::encode($this->controller->MispAttribute->result), $response->body());
        $this->assertSame('no-store', $response->headers['Cache-Control']);
        $this->assertSame(4, $response->headers['X-Rate-Limit-Remaining']);
        $this->assertSame([[$this->controller->Auth->user(), $request]], $this->controller->MispAttribute->calls);
    }

    public function testNumericIocKeysAndEmptyResultsRemainJsonObjects(): void
    {
        $this->controller->MispAttribute->result = ['status' => 'ready', 'scope' => FastLookupConfig::scope(), 'results' => (object)['0' => ['9'], '1' => ['12']]];
        $this->assertInstanceOf(stdClass::class, json_decode($this->controller->fastLookup()->body())->results);
        $this->controller->MispAttribute->result = null;
        $this->controller->request->data = ['value' => []];
        $this->assertInstanceOf(stdClass::class, json_decode($this->controller->fastLookup()->body())->results);
    }

    public function testConfiguredCorsHeadersRemainAvailable(): void
    {
        Configure::write('Security.allow_cors', true);
        Configure::write('Security.cors_origins', 'https://client.example');
        $response = $this->controller->fastLookup();
        $this->assertSame(['https://client.example'], $response->headers['Access-Control-Allow-Origin']);
        $this->assertStringContainsString('Authorization', $response->headers['Access-Control-Allow-Headers']);
        $this->assertSame('no-store', $response->headers['Cache-Control']);
    }

    public function testResponseCannotBecomeSqlDebugDataOrConditionalHttpCacheResponse(): void
    {
        Configure::write('debug', 2);
        $this->controller->request->params['named']['sql'] = '2';
        $_SERVER['HTTP_IF_NONE_MATCH'] = '"' . sha1('{}') . '"';
        try {
            $response = $this->controller->fastLookup();
            $this->assertSame(200, $response->statusCode());
            $this->assertInstanceOf(stdClass::class, json_decode($response->body())->results);
            $this->assertSame('no-store', $response->headers['Cache-Control']);
        } finally {
            unset($_SERVER['HTTP_IF_NONE_MATCH']);
        }
    }

    /** @dataProvider disabledSettings */
    public function testDisabledFeatureDoesNotQueryTheModel($setting): void
    {
        Configure::write('MISP.fast_lookup_enabled', $setting);
        $this->assertRejected(403);
        $this->assertSame([], $this->controller->MispAttribute->calls);
    }

    public function disabledSettings(): array { return [[null], [false], ['0']]; }

    /** @dataProvider nonPostMethods */
    public function testNonPostMethodsAreRejected($method): void
    {
        $this->controller->request->method = $method;
        $this->assertRejected(405);
        $this->assertSame([], $this->controller->MispAttribute->calls);
    }

    public function nonPostMethods(): array { return [['GET'], ['PUT'], ['DELETE']]; }

    public function testBrowserRequestsAreRejected(): void
    {
        $this->controller->rest = false;
        $this->assertRejected(400);
    }

    /** @dataProvider invalidContentTypes */
    public function testNonJsonContentTypesAreRejected($type): void
    {
        $this->controller->request->contentType = $type;
        $this->assertRejected(400);
    }

    public function invalidContentTypes(): array
    {
        return [['application/xml'], ['application/x-www-form-urlencoded'], [''], ['text/json']];
    }

    public function testJsonContentTypeAllowsCharsetParameter(): void
    {
        $this->controller->request->contentType = 'application/json; charset=UTF-8';
        $this->assertInstanceOf(stdClass::class, json_decode($this->controller->fastLookup()->body())->results);
    }

    public function testMalformedBodyCannotReachArrayTypedModel(): void
    {
        $this->controller->request->data = null;
        $this->assertRejected(400);
    }

    /** @dataProvider malformedJsonBodies */
    public function testInputDecoderRejectsMalformedJsonAndNonObjectDocuments($body): void
    {
        $this->controller->beforeFilter();
        $this->assertArrayHasKey('json', $this->controller->RequestHandler->callbacks);
        $decode = $this->controller->RequestHandler->callbacks['json'][0];
        $this->controller->request->data = $decode($body);
        $this->assertRejected(400);
    }

    public function malformedJsonBodies(): array
    {
        return [['{"value":'], ['null'], ['[]'], ['"example.org"'], [''], ['false']];
    }

    /** @dataProvider actionSpellings */
    public function testDecoderPreservesNestedObjectSoModelCanRejectNonListValues($action): void
    {
        $this->controller->request->action = $action;
        $this->controller->request->params['action'] = $action;
        $this->controller->beforeFilter();
        $this->assertArrayHasKey('json', $this->controller->RequestHandler->callbacks);
        $decode = $this->controller->RequestHandler->callbacks['json'][0];
        $decoded = $decode('{"value":{"0":"example.org"}}');
        $this->assertInstanceOf(stdClass::class, $decoded['value']);
        $this->assertSame(['value' => ['example.org']], $decode('{"value":["example.org"]}'));
    }

    public function actionSpellings(): array
    {
        return [['fastLookup'], ['fastlookup'], ['FASTLOOKUP']];
    }

    public function testInvalidModelRequestBecomesBadRequest(): void
    {
        $this->controller->MispAttribute->exception = new InvalidArgumentException('Unknown fastLookup option.');
        $this->assertRejected(400);
    }

    public function testResourceCapBecomes413WithoutAPartialMapping(): void
    {
        $this->controller->MispAttribute->exception = new OverflowException('Candidate row limit exceeded.');
        $this->assertRejected(413);
    }

    /** @dataProvider actionSpellings */
    public function testSearchDisabledRoleCannotBypassRateLimitUsingFastLookup($action): void
    {
        $limiter = new RateLimitComponent();
        $this->expectException(MethodNotAllowedException::class);
        $limiter->check(['Role' => ['enforce_rate_limit' => true, 'rate_limit_count' => 0]], 'attributes', $action);
    }

    public function testWarmingReturns503WithScopeAndProgressWithoutResults(): void
    {
        $this->controller->MispAttribute->result = ['status' => 'warming', 'scope' => FastLookupConfig::scope(), 'progress' => ['processed_events' => 1100, 'total_events' => 1300, 'eta_seconds' => 20]];
        $response = $this->controller->fastLookup();
        $this->assertSame(503, $response->statusCode());
        $this->assertSame('5', $response->headers['Retry-After']);
        $this->assertSame(1100, json_decode($response->body(), true)['progress']['processed_events']);
        $this->assertArrayNotHasKey('results', json_decode($response->body(), true));
    }

    public function testInvalidConfigurationReportsConfiguredTypesWithoutPretendingScopeIsValid(): void
    {
        Configure::write('MISP.fast_lookup_attribute_types', 'domain,unknown-type');
        Configure::write('MISP.fast_lookup_max_values', 0);
        $response = $this->controller->fastLookup();
        $body = json_decode($response->body(), true);
        $this->assertSame(503, $response->statusCode());
        $this->assertIsArray($body['scope']);
        $this->assertSame(['domain', 'unknown-type'], $body['scope']['attribute_types']);
        $this->assertFalse($body['scope']['configuration_valid']);
        $this->assertNull($body['scope']['max_values']);
        $this->assertArrayNotHasKey('results', $body);
        $this->assertSame([], $this->controller->MispAttribute->calls);
    }

    private function assertRejected($status): void
    {
        try {
            $response = $this->controller->fastLookup();
            $this->assertSame($status, $response->statusCode());
            if ($status === 405) {
                $this->assertSame('POST', $response->headers['Allow']);
            }
            $body = json_decode($response->body(), true);
            $this->assertSame(FastLookupConfig::scope(), $body['scope']);
            $this->assertArrayNotHasKey('results', $body);
        } catch (HttpException $e) {
            $this->fail('Feature errors must include a scoped JSON envelope; received exception ' . $e->getCode());
        }
    }
}
