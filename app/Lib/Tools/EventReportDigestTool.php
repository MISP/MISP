<?php

/**
 * What a list says of an event report besides its name: an excerpt of its
 * text, its length in words and the MISP elements it references. Shared by
 * the reports indexes and the value page's Event reports card.
 */
class EventReportDigestTool
{
    const EXCERPT_LENGTH = 400;

    /**
     * @param string|null $content the report's markdown
     * @return array ['excerpt' => string, 'words' => int, 'elements' => [kind => count]]
     */
    public static function digest($content)
    {
        $content = preg_replace('/\r\n?/', "\n", (string)$content);
        $elements = [];
        if (preg_match_all('/@\[(\w+)\]\(([^)\s]+)\)/', $content, $refs, PREG_SET_ORDER)) {
            foreach ($refs as $ref) {
                $elements[$ref[1]][$ref[2]] = true;
            }
        }
        $markup = [
            '/^[ \t]*(`{3,}|~{3,}).*?^[ \t]*\1[ \t]*$/ms' => '',
            '/@\[\w+\]\([^)]*\)/' => '',
            '/!\[[^\]]*\]\([^)]*\)/' => '',
            '/\[([^\]]*)\]\([^)]*\)/' => '$1',
            '/<[^>]*>/' => '',
            '/^[ \t]*(?:[-*_][ \t]*){3,}$/m' => '',
            '/^[ \t]*=+[ \t]*$/m' => '',
            '/^[ \t|:-]*-{3,}[ \t|:-]*$/m' => '',
            '/^[ \t]*(?:#{1,6}|>+|[-*+](?=\s)|\d+[.)](?=\s))[ \t]*/m' => '',
            '/\*\*|~~|[*`|]/' => ' ',
        ];
        $text = preg_replace(array_keys($markup), $markup, $content);
        if ($text === null) {
            // Past PCRE's limits on a long report: the code blocks stay in.
            $markup = array_slice($markup, 1, null, true);
            $text = preg_replace(array_keys($markup), $markup, $content) ?? $content;
        }
        $text = trim(preg_replace('/\s+/u', ' ', (string)$text));
        return [
            'excerpt' => mb_substr($text, 0, self::EXCERPT_LENGTH),
            'words' => $text === '' ? 0 : count(preg_split('/\s+/u', $text)),
            'elements' => array_map('count', $elements),
        ];
    }
}
