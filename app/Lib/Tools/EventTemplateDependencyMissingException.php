<?php

/**
 * Thrown when event-templating code requires a composer package that has not
 * been installed on this MISP instance. Carries the missing package list so
 * callers (controllers, shells, REST responders) can surface a clear
 * "contact your administrator to run `cd app && composer install`" message
 * instead of a raw exception trace.
 *
 * See docs/dev/event-templating-prd.md §11.2.
 */
class EventTemplateDependencyMissingException extends RuntimeException
{
    /** @var string[] */
    private $missingPackages;

    /**
     * @param string[] $missingPackages
     */
    public function __construct(array $missingPackages, $previous = null)
    {
        $this->missingPackages = array_values($missingPackages);
        $message = sprintf(
            'Event templating requires PHP packages that are not installed: %s. '
            . 'Ask your MISP administrator to run `cd app && composer install`.',
            implode(', ', $this->missingPackages)
        );
        parent::__construct($message, 0, $previous);
    }

    /**
     * @return string[]
     */
    public function getMissingPackages()
    {
        return $this->missingPackages;
    }
}
