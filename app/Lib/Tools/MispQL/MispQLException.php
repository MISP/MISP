<?php

/**
 * A MispQL statement refused at a place in its text. Offsets count Unicode
 * code points of the submitted text; messages are fixed texts that never
 * quote it.
 */
class MispQLException extends Exception
{
    const SYNTAX = 'syntax';
    const UNKNOWN_TABLE = 'unknown_table';
    const WRONG_TABLE = 'wrong_table';
    const NOT_SORTABLE = 'not_sortable';
    const BAD_CLAUSE = 'bad_clause';
    const MISSING_CLAUSE = 'missing_clause';
    const LIMIT_EXCEEDED = 'limit_exceeded';
    const CLIENT_STATEMENT = 'client_statement';

    /** @var string */
    private $errorCode;

    /** @var int */
    private $start;

    /** @var int */
    private $end;

    /** @var bool */
    private $atEnd;

    /**
     * @param string $message
     * @param string $code one of the constants above
     * @param int $start
     * @param int|null $end defaults to one code point after $start
     * @param bool $atEnd the text ran out, so more input may complete it
     */
    public function __construct($message, $code, $start, $end = null, $atEnd = false)
    {
        parent::__construct($message);
        $this->errorCode = $code;
        $this->start = $start;
        $this->end = $end === null ? $start + 1 : $end;
        $this->atEnd = $atEnd;
    }

    /**
     * @return string
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }

    /**
     * @return int
     */
    public function getStart()
    {
        return $this->start;
    }

    /**
     * @return int
     */
    public function getEnd()
    {
        return $this->end;
    }

    /**
     * @return bool
     */
    public function isAtEnd()
    {
        return $this->atEnd;
    }

    /**
     * @return array code, message, start and end
     */
    public function toArray()
    {
        return [
            'code' => $this->errorCode,
            'message' => $this->getMessage(),
            'start' => $this->start,
            'end' => $this->end,
        ];
    }
}
