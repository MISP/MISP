<?php
App::uses('JsonTool', 'Tools');

/** Pagination state for the opt-in minimal event sync index. */
class EventIndexSyncTool
{
    const MAX_PAGE_SIZE = 10000;

    public static function requestHash(array $request)
    {
        foreach ($request as &$value) {
            if (is_array($value)) {
                $value = self::canonicalize($value);
            }
        }
        unset($value);
        ksort($request);
        return hash('sha256', JsonTool::encode($request));
    }

    private static function canonicalize(array $value)
    {
        foreach ($value as &$item) {
            if (is_array($item)) {
                $item = self::canonicalize($item);
            }
        }
        unset($item);
        ksort($value);
        return $value;
    }

    public static function encodeCursor($after, $upperBound, $scope, $secret)
    {
        $payload = base64_encode(JsonTool::encode([
            'after' => $after, 'upper_bound' => $upperBound, 'scope' => $scope,
        ]));
        return $payload . '.' . hash_hmac('sha256', $payload, $secret);
    }

    public static function decodeCursor($cursor, $scope, $secret)
    {
        if (!is_string($cursor) || strlen($cursor) > 1024) {
            throw new InvalidArgumentException('Invalid event index cursor.');
        }
        $parts = explode('.', $cursor);
        if (count($parts) !== 2 || !hash_equals(
            hash_hmac('sha256', $parts[0], $secret), $parts[1]
        )) {
            throw new InvalidArgumentException('Invalid event index cursor.');
        }
        $payload = base64_decode($parts[0], true);
        $state = $payload === false ? null : JsonTool::decode($payload);
        if (!is_array($state) || ($state['scope'] ?? null) !== $scope ||
            !isset($state['after'], $state['upper_bound']) ||
            !is_int($state['after']) || !is_int($state['upper_bound']) ||
            $state['after'] < 0 || $state['upper_bound'] < $state['after']
        ) {
            throw new InvalidArgumentException('Invalid event index cursor.');
        }
        return $state;
    }

    public static function resultCount($value)
    {
        if (!is_string($value) && !is_int($value)) {
            return null;
        }
        $value = (string)$value;
        if (!ctype_digit($value) || strlen($value) > strlen((string)PHP_INT_MAX) ||
            (strlen($value) === strlen((string)PHP_INT_MAX) &&
                strcmp($value, (string)PHP_INT_MAX) > 0)
        ) {
            return null;
        }
        return (int)$value;
    }

    /** Validate continuation before processing any events or cached data. */
    public static function validatePage(array $page, $after, $upperBound = null)
    {
        $meta = $page['pagination'] ?? null;
        if (!isset($page['events']) || !is_array($page['events']) ||
            !is_array($meta) || ($meta['version'] ?? null) !== 1 ||
            !isset($meta['has_more'], $meta['after'], $meta['upper_bound'],
                $meta['limit']) || !is_bool($meta['has_more']) ||
            !is_int($meta['after']) || !is_int($meta['upper_bound']) ||
            !is_int($meta['limit']) || $meta['limit'] < 1 ||
            $meta['limit'] > self::MAX_PAGE_SIZE ||
            count($page['events']) > $meta['limit'] ||
            $meta['after'] < $after || $meta['upper_bound'] < $meta['after'] ||
            ($upperBound !== null && $upperBound !== $meta['upper_bound']) ||
            !array_key_exists('next_cursor', $meta) ||
            ($meta['has_more'] && ($meta['after'] <= $after ||
                $meta['after'] >= $meta['upper_bound'] ||
                !is_string($meta['next_cursor']) || $meta['next_cursor'] === '')) ||
            (!$meta['has_more'] && $meta['next_cursor'] !== null)
        ) {
            throw new UnexpectedValueException(
                'Invalid or non-advancing event index pagination.'
            );
        }
        $previousId = $after;
        foreach ($page['events'] as $event) {
            $id = is_array($event) ? self::resultCount($event['id'] ?? null) : null;
            if ($id === null || $id <= $previousId || $id > $meta['after'] ||
                !isset($event['uuid']) || !is_string($event['uuid']) ||
                $event['uuid'] === '') {
                throw new UnexpectedValueException('Invalid event index page.');
            }
            $previousId = $id;
        }
        return $meta;
    }
}
