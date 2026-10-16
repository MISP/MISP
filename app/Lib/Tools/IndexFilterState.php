<?php

/**
 * An index's filters as its URL carries them (CakePHP named segments, or the
 * query string for an index whose values may hold a '/'), and the URLs one
 * change away from them.
 */
class IndexFilterState
{
    const PAGINATOR_KEYS = ['sort', 'direction', 'page', 'limit'];

    /** @var string */
    private $base;

    /** @var string prefix of every filter key, 'search' in event mode */
    private $prefix;

    /** @var array raw key => value, in URL order */
    private $named;

    /** @var array raw key => values, for the keys the URL carries as `key[i]:` */
    private $lists = [];

    /** @var array|null sort / direction / limit named segments, in query mode */
    private $paging = null;

    /**
     * @param string $base index URL with no state on it
     * @param array $named the request's named params
     * @param string $prefix
     * @param array|null $query the request's query, when the filters ride there
     */
    public function __construct($base, array $named, $prefix = '', $query = null)
    {
        $this->base = $base;
        $this->prefix = $prefix;
        $this->named = [];
        if ($query !== null) {
            $this->paging = array_intersect_key($named, array_flip(['sort', 'direction', 'limit']));
            $named = array_filter((array)$query, 'is_string');
        }
        foreach ($named as $key => $value) {
            if (is_array($value)) {
                $this->lists[(string)$key] = array_map('strval', array_values($value));
                $value = implode('|', $value);
            }
            if ((string)$value !== '') {
                $this->named[(string)$key] = (string)$value;
            }
        }
    }

    /**
     * @return array filter name (unprefixed) => value, paginator keys left out
     */
    public function filters()
    {
        $out = [];
        foreach ($this->named as $key => $value) {
            if (in_array($key, self::PAGINATOR_KEYS, true)) {
                continue;
            }
            if ($this->prefix !== '') {
                if (strpos($key, $this->prefix) !== 0) {
                    continue;
                }
                $key = substr($key, strlen($this->prefix));
            }
            $out[$key] = $value;
        }
        return $out;
    }

    /**
     * @param string $name unprefixed
     * @return string|null
     */
    public function get($name)
    {
        return $this->named[$this->prefix . $name] ?? null;
    }

    /**
     * @param string $name unprefixed
     * @return array|null the values of a filter the URL carries as a list
     */
    public function getList($name)
    {
        return $this->lists[$this->prefix . $name] ?? null;
    }

    /**
     * @param string $name unprefixed
     * @return string the key the URL carries
     */
    public function key($name)
    {
        return $this->prefix . $name;
    }

    /**
     * A URL with these filters changed; null removes one. Paging restarts.
     *
     * @param array $changes unprefixed name => value|list|null
     * @return string
     */
    public function url(array $changes)
    {
        $named = $this->named;
        $lists = $this->lists;
        unset($named['page']);
        foreach ($changes as $name => $value) {
            $key = $this->prefix . $name;
            unset($lists[$key]);
            if (is_array($value)) {
                $lists[$key] = array_map('strval', array_values($value));
                $named[$key] = implode('|', $value);
            } elseif ($value === null || (string)$value === '') {
                unset($named[$key]);
            } else {
                $named[$key] = (string)$value;
            }
        }
        return $this->format($named, $lists);
    }

    /**
     * Every filter dropped except the given ones; the sort is kept.
     *
     * @param array $keep unprefixed names
     * @return string
     */
    public function clearUrl(array $keep)
    {
        $named = [];
        foreach ($this->named as $key => $value) {
            $plain = $this->prefix !== '' && strpos($key, $this->prefix) === 0
                ? substr($key, strlen($this->prefix)) : $key;
            if (in_array($key, ['sort', 'direction', 'limit'], true) || in_array($plain, $keep, true)) {
                $named[$key] = $value;
            }
        }
        return $this->format($named, $this->lists);
    }

    /**
     * Split a picker value (`a|!b`) into its parts.
     *
     * @param string|null $value
     * @param string $separator
     * @return array [value, excluded][]
     */
    public static function pieces($value, $separator = '|')
    {
        $out = [];
        foreach (explode($separator, (string)$value) as $piece) {
            $piece = trim($piece);
            if ($piece === '' || $piece === '!') {
                continue;
            }
            $excluded = $piece[0] === '!';
            $out[] = [$excluded ? substr($piece, 1) : $piece, $excluded];
        }
        return $out;
    }

    /**
     * @param array $pieces [value, excluded][]
     * @param string $separator
     * @return string|null
     */
    public static function join(array $pieces, $separator = '|')
    {
        $parts = [];
        foreach ($pieces as [$value, $excluded]) {
            $parts[] = ($excluded ? '!' : '') . $value;
        }
        return $parts ? implode($separator, $parts) : null;
    }

    private function format(array $named, array $lists = [])
    {
        $url = $this->base;
        if ($this->paging !== null) {
            foreach ($this->paging as $key => $value) {
                $url .= '/' . $key . ':' . rawurlencode((string)$value);
            }
            $query = http_build_query(array_diff_key($named, array_flip(self::PAGINATOR_KEYS)), '', '&', PHP_QUERY_RFC3986);
            return $url . ($query === '' ? '' : '?' . $query);
        }
        foreach ($named as $key => $value) {
            if (isset($lists[$key])) {
                foreach ($lists[$key] as $i => $item) {
                    $url .= '/' . $key . '[' . $i . ']:' . rawurlencode($item);
                }
                continue;
            }
            $url .= '/' . $key . ':' . rawurlencode($value);
        }
        return $url;
    }
}
