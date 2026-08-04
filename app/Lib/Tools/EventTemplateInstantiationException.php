<?php

/**
 * Raised by EventTemplateInstantiator when the instantiation of an event
 * from a template fails. Carries a structured list of human-readable error
 * strings so the caller (Phase 1.5 controller, REST responder, shell) can
 * surface them to the end user.
 *
 * See docs/dev/event-templating-prd.md §5.2 F2.10 (transactional creation,
 * structured errors on failure).
 */
class EventTemplateInstantiationException extends RuntimeException
{
    /** @var string[] */
    private $errors;

    /**
     * @param string   $message
     * @param string[] $errors   human-readable failure reasons
     */
    public function __construct($message, array $errors = array(), $previous = null)
    {
        $this->errors = array_values($errors);
        parent::__construct($message, 0, $previous);
    }

    /**
     * @return string[]
     */
    public function getErrors()
    {
        return $this->errors;
    }
}
