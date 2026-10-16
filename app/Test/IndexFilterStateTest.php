<?php
require_once __DIR__ . '/../Lib/Tools/IndexFilterState.php';

use PHPUnit\Framework\TestCase;

class IndexFilterStateTest extends TestCase
{
    private function state(array $named)
    {
        return new IndexFilterState('/events/index', $named, 'search');
    }

    public function testFiltersDropThePrefixAndThePaginator()
    {
        $state = $this->state([
            'searchorg' => '9|!63',
            'searchemail' => 'a@b.c',
            'sort' => 'Event.id',
            'page' => '3',
            'other' => 'x',
            'searchtag' => '',
        ]);
        $this->assertSame(['org' => '9|!63', 'email' => 'a@b.c'], $state->filters());
        $this->assertSame('9|!63', $state->get('org'));
        $this->assertNull($state->get('tag'));
    }

    public function testUrlChangesOneFilterRestartsPagingAndKeepsTheSort()
    {
        $state = $this->state(['searchpublished' => '0', 'sort' => 'Event.id', 'direction' => 'asc', 'page' => '2']);
        $this->assertSame(
            '/events/index/searchpublished:0/sort:Event.id/direction:asc/searchpending:1',
            $state->url(['pending' => '1'])
        );
        $this->assertSame(
            '/events/index/sort:Event.id/direction:asc',
            $state->url(['published' => null])
        );
    }

    public function testUrlEncodesValues()
    {
        $state = $this->state([]);
        $this->assertSame(
            '/events/index/searchgalaxy:misp-galaxy%3Athreat-actor%3D%22Sofacy%22%7C%21tlp%3Ared',
            $state->url(['galaxy' => 'misp-galaxy:threat-actor="Sofacy"|!tlp:red'])
        );
    }

    public function testClearKeepsTheScopeAndTheSort()
    {
        $state = $this->state([
            'searchemail' => 'a@b.c',
            'searchorg' => '9',
            'searchtimestamp' => '7d',
            'sort' => 'Event.date',
            'page' => '4',
        ]);
        $this->assertSame('/events/index/searchemail:a%40b.c/sort:Event.date', $state->clearUrl(['email']));
    }

    public function testPiecesRoundTrip()
    {
        $pieces = IndexFilterState::pieces('9| !63 ||!');
        $this->assertSame([['9', false], ['63', true]], $pieces);
        $this->assertSame('9|!63', IndexFilterState::join($pieces));
        $this->assertNull(IndexFilterState::join([]));
    }

    public function testArrayValuesAreJoined()
    {
        $state = $this->state(['searchdistribution' => ['0', '3']]);
        $this->assertSame('0|3', $state->get('distribution'));
    }

    public function testListValuesKeepTheirShapeInUrls()
    {
        $state = $this->state(['searchtimestamp' => ['2026-09-01', '2026-09-30T23:59:59'], 'searchorg' => '9']);
        $this->assertSame(['2026-09-01', '2026-09-30T23:59:59'], $state->getList('timestamp'));
        $this->assertNull($state->getList('org'));
        $this->assertSame(
            '/events/index/searchtimestamp[0]:2026-09-01/searchtimestamp[1]:2026-09-30T23%3A59%3A59',
            $state->url(['org' => null])
        );
        $this->assertSame('/events/index/searchtimestamp:7d/searchorg:9', $state->url(['timestamp' => '7d']));
        $this->assertSame(
            '/events/index/searchorg:9/searchpublish_timestamp[0]:0/searchpublish_timestamp[1]:1700000000',
            $state->url(['timestamp' => null, 'publish_timestamp' => ['0', '1700000000']])
        );
    }

    public function testDoublePipeSeparator()
    {
        $pieces = IndexFilterState::pieces('csv||misp||', '||');
        $this->assertSame([['csv', false], ['misp', false]], $pieces);
        $this->assertSame('csv||misp', IndexFilterState::join($pieces, '||'));
    }

    public function testQueryTransportKeepsFiltersInTheQuery()
    {
        $state = new IndexFilterState(
            '/attributes/index',
            ['sort' => 'Attribute.type', 'page' => '3'],
            '',
            ['value' => 'https://a/b', 'tags' => 'tlp:red||!tlp:white', 'page' => '2']
        );
        $this->assertSame(['value' => 'https://a/b', 'tags' => 'tlp:red||!tlp:white'], $state->filters());
        $this->assertSame(
            '/attributes/index/sort:Attribute.type?value=https%3A%2F%2Fa%2Fb&tags=tlp%3Ared',
            $state->url(['tags' => 'tlp:red'])
        );
        $this->assertSame('/attributes/index/sort:Attribute.type', $state->clearUrl([]));
    }

    public function testKeyCarriesThePrefix()
    {
        $this->assertSame('searchorg', $this->state([])->key('org'));
    }
}
