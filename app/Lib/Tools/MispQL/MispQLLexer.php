<?php
require_once __DIR__ . '/MispQLException.php';

/**
 * Splits MispQL text into tokens, one at a time. The whole text is read once
 * when the lexer is built, so an error here wins over any parse error; the
 * parser then asks for tokens as it goes, and none is kept.
 *
 * A token is an array: kind (KEYWORD, NAME, STRING, INT, SYMBOL or EOF),
 * value, start, end, and quoted for a backtick name. Offsets count code
 * points. An INT's value is its digits as written.
 */
class MispQLLexer
{
    const MAX_LENGTH = 1048576;
    const MAX_INT = '9223372036854775807';

    const KEYWORDS = [
        'AND' => true, 'ASC' => true, 'BY' => true, 'COUNT' => true,
        'DATABASES' => true, 'DESC' => true, 'DESCRIBE' => true,
        'FALSE' => true, 'FORMAT' => true, 'FROM' => true, 'IN' => true,
        'LIKE' => true, 'LIMIT' => true, 'NOT' => true, 'OFFSET' => true,
        'OR' => true, 'ORDER' => true, 'SELECT' => true, 'SHOW' => true,
        'TABLES' => true, 'TRUE' => true, 'USE' => true, 'WHERE' => true,
        'WHOAMI' => true,
    ];

    const WORD_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
    const DIGITS = '0123456789';
    const SYMBOLS_2 = ['!=' => true, '<>' => true, '<=' => true, '>=' => true];
    const SYMBOLS_1 = [
        '=' => true, '<' => true, '>' => true, '(' => true, ')' => true,
        ',' => true, '.' => true, '*' => true, ';' => true, '-' => true,
    ];

    // Unicode's White_Space, 25 code points: text pasted from web pages,
    // chats or PDFs brings U+00A0 and its kin.
    const ASCII_SPACE = [
        "\t" => true, "\n" => true, "\x0B" => true, "\x0C" => true,
        "\r" => true, ' ' => true,
    ];
    const UNICODE_SPACE = [
        "\u{85}" => true, "\u{A0}" => true, "\u{1680}" => true,
        "\u{2000}" => true, "\u{2001}" => true, "\u{2002}" => true,
        "\u{2003}" => true, "\u{2004}" => true, "\u{2005}" => true,
        "\u{2006}" => true, "\u{2007}" => true, "\u{2008}" => true,
        "\u{2009}" => true, "\u{200A}" => true, "\u{2028}" => true,
        "\u{2029}" => true, "\u{202F}" => true, "\u{205F}" => true,
        "\u{3000}" => true,
    ];

    // What Python's str.isdigit() accepts beyond 0-9 (Unicode 15.0), which
    // mispql 1.x applies to the character after "1.".
    const OTHER_DIGITS = '\x{B2}-\x{B3}\x{B9}\x{660}-\x{669}\x{6F0}-\x{6F9}'
        . '\x{7C0}-\x{7C9}\x{966}-\x{96F}\x{9E6}-\x{9EF}\x{A66}-\x{A6F}'
        . '\x{AE6}-\x{AEF}\x{B66}-\x{B6F}\x{BE6}-\x{BEF}\x{C66}-\x{C6F}'
        . '\x{CE6}-\x{CEF}\x{D66}-\x{D6F}\x{DE6}-\x{DEF}\x{E50}-\x{E59}'
        . '\x{ED0}-\x{ED9}\x{F20}-\x{F29}\x{1040}-\x{1049}\x{1090}-\x{1099}'
        . '\x{1369}-\x{1371}\x{17E0}-\x{17E9}\x{1810}-\x{1819}'
        . '\x{1946}-\x{194F}\x{19D0}-\x{19DA}\x{1A80}-\x{1A89}'
        . '\x{1A90}-\x{1A99}\x{1B50}-\x{1B59}\x{1BB0}-\x{1BB9}'
        . '\x{1C40}-\x{1C49}\x{1C50}-\x{1C59}\x{2070}\x{2074}-\x{2079}'
        . '\x{2080}-\x{2089}\x{2460}-\x{2468}\x{2474}-\x{247C}'
        . '\x{2488}-\x{2490}\x{24EA}\x{24F5}-\x{24FD}\x{24FF}'
        . '\x{2776}-\x{277E}\x{2780}-\x{2788}\x{278A}-\x{2792}'
        . '\x{A620}-\x{A629}\x{A8D0}-\x{A8D9}\x{A900}-\x{A909}'
        . '\x{A9D0}-\x{A9D9}\x{A9F0}-\x{A9F9}\x{AA50}-\x{AA59}'
        . '\x{ABF0}-\x{ABF9}\x{FF10}-\x{FF19}\x{104A0}-\x{104A9}'
        . '\x{10A40}-\x{10A43}\x{10D30}-\x{10D39}\x{10E60}-\x{10E68}'
        . '\x{11052}-\x{1105A}\x{11066}-\x{1106F}\x{110F0}-\x{110F9}'
        . '\x{11136}-\x{1113F}\x{111D0}-\x{111D9}\x{112F0}-\x{112F9}'
        . '\x{11450}-\x{11459}\x{114D0}-\x{114D9}\x{11650}-\x{11659}'
        . '\x{116C0}-\x{116C9}\x{11730}-\x{11739}\x{118E0}-\x{118E9}'
        . '\x{11950}-\x{11959}\x{11C50}-\x{11C59}\x{11D50}-\x{11D59}'
        . '\x{11DA0}-\x{11DA9}\x{11F50}-\x{11F59}\x{16A60}-\x{16A69}'
        . '\x{16AC0}-\x{16AC9}\x{16B50}-\x{16B59}\x{1D7CE}-\x{1D7FF}'
        . '\x{1E140}-\x{1E149}\x{1E2F0}-\x{1E2F9}\x{1E4F0}-\x{1E4F9}'
        . '\x{1E950}-\x{1E959}\x{1F100}-\x{1F10A}\x{1FBF0}-\x{1FBF9}';

    /** @var string */
    private $text;
    /** @var int */
    private $bytes;
    /** @var int code points of the text */
    private $length;
    /** @var int byte position */
    private $i = 0;
    /** @var int code point position */
    private $cp = 0;
    /** @var int end of the last token read; where EOF sits */
    private $lastEnd = 0;

    /**
     * @param string $text
     * @throws MispQLException
     */
    public function __construct($text)
    {
        $this->text = $text;
        $this->bytes = strlen($text);
        $this->length = mb_strlen($text, 'UTF-8');
        if ($this->length > self::MAX_LENGTH) {
            throw new MispQLException(
                'too long: at most ' . self::MAX_LENGTH . ' characters',
                MispQLException::LIMIT_EXCEEDED,
                self::MAX_LENGTH,
                $this->length
            );
        }
        if (!preg_match('//u', $text)) {
            throw new MispQLException('the text is not valid UTF-8', MispQLException::SYNTAX, 0, 0);
        }
        while ($this->next()['kind'] !== 'EOF') {
        }
        $this->i = 0;
        $this->cp = 0;
        $this->lastEnd = 0;
    }

    /**
     * @param string $text valid UTF-8
     * @return int
     */
    public static function codePoints($text)
    {
        return mb_strlen($text, 'UTF-8');
    }

    /**
     * @param string $text
     * @param int $start code point offset
     * @param int $end code point offset
     * @return string
     */
    public static function slice($text, $start, $end)
    {
        return mb_substr($text, $start, max(0, $end - $start), 'UTF-8');
    }

    /**
     * The next token; EOF once the text is read, as often as asked.
     *
     * @return array
     * @throws MispQLException
     */
    public function next()
    {
        $text = $this->text;
        while ($this->i < $this->bytes) {
            $i = $this->i;
            $cp = $this->cp;
            $c = $text[$i];
            if (ord($c) >= 0x80) {
                $char = $this->charAt($i);
                if (!isset(self::UNICODE_SPACE[$char])) {
                    throw new MispQLException('unexpected character', MispQLException::SYNTAX, $cp);
                }
                $this->i += strlen($char);
                $this->cp++;
            } elseif (isset(self::ASCII_SPACE[$c])) {
                $this->i++;
                $this->cp++;
            } elseif ($c === '-' && $i + 1 < $this->bytes && $text[$i + 1] === '-') {
                $newline = strpos($text, "\n", $i);
                $end = $newline === false ? $this->bytes : $newline;
                $this->cp += self::codePoints(substr($text, $i, $end - $i));
                $this->i = $end;
            } elseif ($c === '"' || $c === "'") {
                list($value, $end, $endCp) = $this->quoted($i, $cp, $c, 'string');
                return $this->token('STRING', $value, $end, $endCp);
            } elseif ($c === '`') {
                list($value, $end, $endCp) = $this->quoted($i, $cp, '`', 'name');
                if ($value === '') {
                    throw new MispQLException('empty name', MispQLException::SYNTAX, $cp, $endCp);
                }
                return $this->token('NAME', $value, $end, $endCp, true);
            } elseif (strpos(self::WORD_CHARS, $c) !== false) {
                return $this->word($i, strspn($text, self::WORD_CHARS, $i), $cp);
            } else {
                $two = substr($text, $i, 2);
                if (isset(self::SYMBOLS_2[$two])) {
                    $symbol = $two;
                } elseif (isset(self::SYMBOLS_1[$c])) {
                    $symbol = $c;
                } else {
                    $hint = $c === '!' ? '; use != or NOT' : '';
                    throw new MispQLException('unexpected character' . $hint, MispQLException::SYNTAX, $cp);
                }
                $length = strlen($symbol);
                return $this->token('SYMBOL', $symbol, $i + $length, $cp + $length);
            }
        }
        return [
            'kind' => 'EOF',
            'value' => null,
            'start' => $this->lastEnd,
            'end' => $this->lastEnd,
            'quoted' => false,
        ];
    }

    private function token($kind, $value, $end, $endCp, $quoted = false)
    {
        $token = ['kind' => $kind, 'value' => $value, 'start' => $this->cp, 'end' => $endCp, 'quoted' => $quoted];
        $this->i = $end;
        $this->cp = $endCp;
        $this->lastEnd = $endCp;
        return $token;
    }

    /**
     * A quoted string or name; a doubled quote stands for one.
     *
     * @return array value, byte end, code point end
     * @throws MispQLException
     */
    private function quoted($start, $startCp, $quote, $what)
    {
        $text = $this->text;
        $parts = [];
        $i = $start + 1;
        while (true) {
            $end = strpos($text, $quote, $i);
            if ($end === false) {
                throw new MispQLException(
                    "$what not closed",
                    MispQLException::SYNTAX,
                    $startCp,
                    $this->length,
                    true
                );
            }
            $parts[] = substr($text, $i, $end - $i);
            if ($end + 1 < $this->bytes && $text[$end + 1] === $quote) {
                $parts[] = $quote;
                $i = $end + 2;
            } else {
                $end++;
                $endCp = $startCp + self::codePoints(substr($text, $start, $end - $start));
                return [implode('', $parts), $end, $endCp];
            }
        }
    }

    private function word($i, $length, $cp)
    {
        $word = substr($this->text, $i, $length);
        $end = $cp + $length;
        if (strpos(self::DIGITS, $word[0]) === false) {
            $upper = strtoupper($word);
            if (isset(self::KEYWORDS[$upper])) {
                return $this->token('KEYWORD', $upper, $i + $length, $end);
            }
            return $this->token('NAME', strtolower($word), $i + $length, $end);
        }
        if (strspn($word, self::DIGITS) !== $length) {
            throw new MispQLException(
                'a word starting with a digit must be quoted',
                MispQLException::SYNTAX,
                $cp,
                $end
            );
        }
        $after = $i + $length;
        if ($after + 1 < $this->bytes && $this->text[$after] === '.' && $this->isDigit($after + 1)) {
            throw new MispQLException('only whole numbers are supported', MispQLException::SYNTAX, $cp, $end + 1);
        }
        $digits = ltrim($word, '0');
        $max = strlen(self::MAX_INT);
        if (strlen($digits) > $max || (strlen($digits) === $max && strcmp($digits, self::MAX_INT) > 0)) {
            throw new MispQLException(
                'number too large: at most ' . self::MAX_INT,
                MispQLException::SYNTAX,
                $cp,
                $end
            );
        }
        return $this->token('INT', $word, $i + $length, $end);
    }

    /**
     * @param string $digits an INT token's value
     * @return int
     */
    public static function intValue($digits)
    {
        return (int)ltrim($digits, '0');
    }

    private function isDigit($i)
    {
        $char = $this->charAt($i);
        if (strlen($char) === 1) {
            return strpos(self::DIGITS, $char) !== false;
        }
        return preg_match('/^[' . self::OTHER_DIGITS . ']$/u', $char) === 1;
    }

    /**
     * The UTF-8 character starting at byte $i.
     */
    private function charAt($i)
    {
        $lead = ord($this->text[$i]);
        $length = $lead < 0x80 ? 1 : ($lead >= 0xF0 ? 4 : ($lead >= 0xE0 ? 3 : 2));
        return substr($this->text, $i, $length);
    }
}
