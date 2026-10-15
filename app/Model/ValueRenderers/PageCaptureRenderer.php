<?php

/**
 * What a URL looked like when somebody fetched it.
 *
 * **One module draws this today, and it is a keyed one.**
 * `rst_screenshot` emits an `image` object with the PNG attached, so
 * a reader whose instance has that key sees the widget. The free
 * answers are still prose: `sourcecache` holds the page bytes as an
 * attachment and emits no object, and `urlscan` holds a screenshot
 * URL, a title and a server banner and emits none of it.
 *
 * **`page-capture` is claimed here in advance**, the way `reputation`
 * is. `image` carries a picture and no date and `domain-crawled`
 * carries the URLs a crawl found rather than what they returned, so
 * neither can say *when* a page looked like this — which is the one
 * fact a capture is read for. The day a template for the capture
 * itself lands, the two conversions have somewhere to emit that
 * already has a widget.
 *
 * **A capture with no image is still a capture.** An archived copy and
 * its extracted text are what a disinformation reader came for as much
 * as the picture is, so the widget draws a thumbnail where there is
 * one and the URL and its date where there is not.
 */
class PageCaptureRenderer extends ValueRendererBase
{
    public $id = 'page-capture';

    public $templates = array(
        'image',
        'domain-crawled',
        'page-capture',
    );

    public $compact = 'Values/Renderers/page_capture_compact';

    public $full = 'Values/Renderers/page_capture_full';

    public $eventUse = self::EVENT_SET;

    public function __construct()
    {
        $this->description = __('A captured copy of a page, with what'
            . ' it looked like.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->captureOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $captures = array();
        foreach ($objects as $object) {
            $capture = $this->captureOf($object);
            if ($capture !== null) {
                $captures[] = $capture;
            }
        }
        usort($captures, function ($a, $b) {
            return ($b['captured'] ?? $b['ran_at'] ?? 0)
                - ($a['captured'] ?? $a['ran_at'] ?? 0);
        });
        return array(
            'captures' => $captures,
            'newest' => empty($captures) ? null : $captures[0],
            'count' => count($captures),
            'sources' => $this->sources($objects),
        );
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function captureOf(array $object)
    {
        $url = $this->firstValue($object, array('url', 'link'));
        $attachment = $this->value($object, 'attachment');
        $archive = $this->value($object, 'archive');
        $text = $this->firstValue($object, array('image-text', 'text'));
        if ($url === null && $attachment === null && $archive === null
            && $text === null
        ) {
            return null;
        }
        return array(
            'url' => $url,
            'domain' => $this->value($object, 'domain'),
            'filename' => $this->value($object, 'filename'),
            /*
             * The attachment relation carries a filename rather than
             * the bytes: what arrives over the wire from a module is a
             * name and a payload the pane already knows how to offer,
             * and a widget that tried to inline it would be drawing
             * something it has not got.
             */
            'attachment' => $attachment,
            'archive' => $archive,
            'text' => $text,
            /*
             * Only `page-capture` carries this. The other two
             * templates date nothing, so the sort falls through to
             * when the module ran - which is the capture date for a
             * module that captured just now and wrong for one that
             * fetched the page out of an archive.
             */
            'captured' => $this->stamp(
                $this->value($object, 'capture-date')
            ),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }
}
