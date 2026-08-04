<?php
App::uses('EventTemplateDependencies', 'Tools');

/**
 * Thin wrapper around league/commonmark that renders Markdown strings to
 * HTML for event-template descriptions, `text_block` elements, `help`,
 * and `help_override` text.
 *
 * Configured with `html_input => strip` so any raw HTML in creator-authored
 * content is dropped rather than rendered, and `allow_unsafe_links => false`
 * so `javascript:` / `data:` URIs in links are filtered. See PRD §11 and
 * §16 (resolved 2026-04-22, Q3).
 *
 * The renderer asserts that `league/commonmark` is installed on first use.
 * If it isn't, an EventTemplateDependencyMissingException is thrown — the
 * caller is expected to catch it and render an admin-facing instruction
 * rather than a raw exception.
 */
class EventTemplateMarkdownRenderer
{
    /** @var \League\CommonMark\ConverterInterface|null */
    private $converter = null;

    /**
     * Render a Markdown string to sanitised HTML. Empty / null input
     * returns the empty string without initialising the converter.
     *
     * @param string|null $markdown
     * @return string
     */
    public function render($markdown)
    {
        if ($markdown === null || $markdown === '') {
            return '';
        }
        return (string) $this->converter()->convert((string) $markdown);
    }

    private function converter()
    {
        if ($this->converter !== null) {
            return $this->converter;
        }
        EventTemplateDependencies::requireSome(array('league/commonmark'));

        $config = array(
            'html_input'         => 'strip',
            'allow_unsafe_links' => false,
        );
        $this->converter = new \League\CommonMark\CommonMarkConverter($config);
        return $this->converter;
    }
}
