<?php

declare(strict_types=1);

use \Helper\Fixture\Data\GalaxyFixture;

class IndexGalaxiesCest
{

    private const URL = '/galaxies';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testPostIndexReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedGalaxy(ApiTester $I)
    {
        $I->haveAuthorizationKey();
        $fakeGalaxy = GalaxyFixture::fake();
        $I->haveInDatabase('galaxies', $fakeGalaxy->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['Galaxy' => $fakeGalaxy->toResponse()]]);
    }

    public function testPostIndexReturnsExpectedGalaxy(ApiTester $I)
    {
        $I->haveAuthorizationKey();
        $fakeGalaxyFoo = GalaxyFixture::fake(['name' => 'foo']);
        $fakeGalaxyBar = GalaxyFixture::fake(['name' => 'bar']);
        $I->haveInDatabase('galaxies', $fakeGalaxyFoo->toDatabase());
        $I->haveInDatabase('galaxies', $fakeGalaxyBar->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'value' => 'foo'
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['Galaxy' => $fakeGalaxyFoo->toResponse()]]);
    }
}
