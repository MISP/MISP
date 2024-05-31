<?php

namespace App\Lib\Tools;

class TrendingTool
{
    private $eventModel;
    public const defaultTagNamespaceForTrends = [
        'misp-galaxy:mitre-attack-pattern',
    ];

    public function __construct($eventModel)
    {
        $this->eventModel = $eventModel;
    }

    public function getTrendsForTags(array $events, int $baseDayRange, int $rollingWindows = 3, $tagFilterPrefixes = null): array
    {
        $tagFilterPrefixes = $tagFilterPrefixes ?: self::defaultTagNamespaceForTrends;
        $clusteredTags = $this->__clusterTagsForRollingWindow($events, $baseDayRange, $rollingWindows, $tagFilterPrefixes);
        $trendAnalysis = $this->__computeTrendAnalysis($clusteredTags);
        return [
            'clustered_tags' => $clusteredTags,
            'trend_analysis' => $trendAnalysis,
        ];
    }

    private function __computeTrendAnalysis(array $clusteredTags): array
    {
        $tagsPerRollingWindow = $clusteredTags['tagsPerRollingWindow'];
        $eventNumberPerRollingWindow = $clusteredTags['eventNumberPerRollingWindow'];
        $trendAnalysis = [];
        $allTimestamps = array_keys($tagsPerRollingWindow);
        $allTags = [];
        foreach ($allTimestamps as $i => $timestamp) {
            $trendAnalysis[$timestamp] = [];
            $tags = $tagsPerRollingWindow[$timestamp];
            $nextTimestamp = isset($allTimestamps[$i + 1]) ? $allTimestamps[$i + 1] : false;
            $previousTimestamp = isset($allTimestamps[$i - 1]) ? $allTimestamps[$i - 1] : false;
            foreach ($tags as $tag => $amount) {
                $rawChange = 0;
                $percentChange = 0;
                if (!empty($nextTimestamp)) {
                    $nextAmount = !empty($tagsPerRollingWindow[$nextTimestamp][$tag]) ? $tagsPerRollingWindow[$nextTimestamp][$tag] : 0;
                    $rawChange = $amount - $nextAmount;
                    $percentChange = 100 * $rawChange / $amount;
                }
                $allTags[$tag] = true;
                $trendAnalysis[$timestamp][$tag] = [
                    'occurrence' => round($amount / $eventNumberPerRollingWindow[$timestamp], 2),
                    'raw_change' => $rawChange,
                    'percent_change' => $percentChange,
                    'change_sign' => $rawChange > 0 ? 1 : ($rawChange < 0 ? -1 : 0),
                ];
            }
            if (!empty($previousTimestamp)) {
                foreach (array_keys($trendAnalysis[$timestamp]) as $tag) {
                    if (empty($trendAnalysis[$previousTimestamp][$tag])) {
                        $trendAnalysis[$previousTimestamp][$tag] = [
                            'occurrence' => 0,
                            'raw_change' => -$amount,
                            'percent_change' => round(100 * (-$amount / $amount), 2),
                            'change_sign' => -$amount > 0 ? 1 : (-$amount < 0 ? -1 : 0),
                        ];
                    }
                }
            }
        }
        return $trendAnalysis;
    }

    private function __clusterTagsForRollingWindow(array $events, int $baseDayRange, int $rollingWindows = 3, $tagFilterPrefixes = null): array
    {
        $fullDayNumber = $baseDayRange + $baseDayRange * $rollingWindows;
        $tagsPerRollingWindow = [];
        $eventNumberPerRollingWindow = [];
        $timestampRollingWindow = [];
        for ($i = 0; $i <= $fullDayNumber; $i += $baseDayRange) {
            $timestamp = $this->eventModel->resolveTimeDelta($i . 'd');
            $timestampRollingWindow[] = $timestamp;
            $tagsPerRollingWindow[$timestamp] = [];
        }
        $tagsPerRollingWindow = array_map(function () {
            return [];
        }, array_flip(array_slice($timestampRollingWindow, 1)));
        $eventNumberPerRollingWindow = array_map(function () {
            return 0;
        }, array_flip(array_slice($timestampRollingWindow, 1)));
        $allTagsPerPrefix = [];

        foreach ($events as $event) {
            $allTags = $this->eventModel->extractAllTagNames($event);
            $rollingTimestamps = $this->__getTimestampFromRollingWindow($event['Event']['timestamp'], $timestampRollingWindow);
            $filteredTags = array_filter($allTags, function ($tag) use ($tagFilterPrefixes, &$allTagsPerPrefix) {
                if (is_null($tagFilterPrefixes)) {
                    return true;
                } else {
                    foreach ($tagFilterPrefixes as $tagPrefix) {
                        if (substr($tag, 0, strlen($tagPrefix)) === $tagPrefix) {
                            $allTagsPerPrefix[$tagPrefix][$tag] = true;
                            return true;
                        }
                    }
                    return false;
                }
            });
            foreach ($filteredTags as $tag) {
                if (empty($tagsPerRollingWindow[$rollingTimestamps['current']][$tag])) {
                    $tagsPerRollingWindow[$rollingTimestamps['current']][$tag] = 0;
                }
                $tagsPerRollingWindow[$rollingTimestamps['current']][$tag] += 1;
            }
            $eventNumberPerRollingWindow[$rollingTimestamps['current']] += 1;
        }
        return [
            'tagsPerRollingWindow' => $tagsPerRollingWindow,
            'eventNumberPerRollingWindow' => $eventNumberPerRollingWindow,
            'allTagsPerPrefix' => array_map(function ($clusteredTags) {
                return array_keys($clusteredTags);
            }, $allTagsPerPrefix),
        ];
    }

    private function __getTimestampFromRollingWindow(int $eventTimestamp, array $rollingWindow): array
    {
        $i = 0;
        if (count($rollingWindow) > 2) {
            for ($i = 0; $i < count($rollingWindow) - 1; $i++) {
                if ($eventTimestamp >= $rollingWindow[$i]) {
                    break;
                }
            }
        }
        return [
            'previous' => isset($rollingWindow[$i - 1]) ? $rollingWindow[$i - 1] : null,
            'current' => $rollingWindow[$i],
            'next' => isset($rollingWindow[$i + 1]) ? $rollingWindow[$i + 1] : null,
        ];
    }
}
