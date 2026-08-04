<?php

/**
 * Raised by EventTemplateImporter when an import cannot be completed.
 * Carries a structured error list so controllers / shells can surface
 * precise failure reasons (schema violations, missing object-template
 * dependencies, uuid collisions, etc.) to the end user.
 */
class EventTemplateImportException extends RuntimeException
{
    /** @var string[] */
    private $errors;

    /**
     * @param string   $message
     * @param string[] $errors
     */
    public function __construct($message, array $errors = array(), $previous = null)
    {
        $this->errors = array_values($errors);
        parent::__construct($message, 0, $previous);
    }

    /** @return string[] */
    public function getErrors()
    {
        return $this->errors;
    }
}
