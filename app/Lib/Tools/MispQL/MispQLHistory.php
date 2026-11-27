<?php

/**
 * The query console's history: the statements a user ran from it, newest
 * first, each once.
 */
class MispQLHistory
{
    const SETTING = 'mispql_history';

    const MAX_ENTRIES = 50;

    /** Encoded size the list is kept under; older entries go first. */
    const MAX_BYTES = 524288;

    /**
     * @param mixed $stored the setting's value
     * @return array<array{statement: string, ran_at: int}>
     */
    public static function entries($stored)
    {
        if (!is_array($stored)) {
            return [];
        }
        $entries = [];
        foreach ($stored as $entry) {
            if (!is_array($entry)
                || !isset($entry['statement'], $entry['ran_at'])
                || !is_string($entry['statement'])
                || $entry['statement'] === ''
            ) {
                continue;
            }
            $entries[] = [
                'statement' => $entry['statement'],
                'ran_at' => (int)$entry['ran_at'],
            ];
            if (count($entries) >= self::MAX_ENTRIES) {
                break;
            }
        }
        return $entries;
    }

    /**
     * Puts the statement on top; running it again moves it rather than
     * repeating it.
     *
     * @param array $entries as entries() returns them
     * @param string $statement
     * @param int $now
     * @return array|null the new list, or null when the statement alone is
     *   too large to keep
     */
    public static function add(array $entries, $statement, $now)
    {
        $statement = trim($statement);
        $entry = ['statement' => $statement, 'ran_at' => (int)$now];
        $size = self::size($entry);
        if ($statement === '' || $size > self::MAX_BYTES) {
            return null;
        }
        $kept = [$entry];
        foreach ($entries as $old) {
            if ($old['statement'] === $statement) {
                continue;
            }
            $size += self::size($old);
            if (count($kept) >= self::MAX_ENTRIES || $size > self::MAX_BYTES) {
                break;
            }
            $kept[] = $old;
        }
        return $kept;
    }

    private static function size(array $entry)
    {
        // As UserSetting stores it
        return strlen(json_encode($entry)) + 1;
    }
}
