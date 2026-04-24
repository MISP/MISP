<?php
App::uses('AppHelper', 'View/Helper');
App::uses('EventTemplateMarkdownRenderer', 'Tools');

/**
 * Thin view-helper wrapper around EventTemplateMarkdownRenderer so
 * the event-templating user-form and view partials can render
 * creator-authored Markdown (PRD §7.2) without every partial
 * re-instantiating the renderer.
 *
 * Configured with html_input=>strip and allow_unsafe_links=>false,
 * so raw HTML tags in the input are dropped as literal text and
 * javascript:/data: URIs are filtered from links.
 */
class EventTemplateMarkdownHelper extends AppHelper
{
    private $renderer = null;

    private function getRenderer()
    {
        if ($this->renderer === null) {
            $this->renderer = new EventTemplateMarkdownRenderer();
        }
        return $this->renderer;
    }

    /**
     * Render a Markdown string to safe HTML. Empty / null input
     * returns an empty string (no surrounding markup), so partials
     * can unconditionally call this helper without an isset() check.
     */
    public function render($markdown)
    {
        if ($markdown === null || $markdown === '') {
            return '';
        }
        return $this->getRenderer()->render((string)$markdown);
    }
}
