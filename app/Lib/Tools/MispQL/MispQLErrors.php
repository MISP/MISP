<?php

/**
 * Statements refused, each error placed on the submitted text.
 */
class MispQLErrors extends Exception
{
    const MAX = 10;

    /** @var array[] statement, start, end, code, message and, for errors
     *    from the query tree, path */
    public $errors;

    /**
     * @param array[] $errors
     */
    public function __construct(array $errors)
    {
        $this->errors = array_slice($errors, 0, self::MAX);
        parent::__construct('Invalid query', 400);
    }
}
