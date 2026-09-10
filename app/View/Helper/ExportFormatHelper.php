<?php
App::uses('AppHelper', 'View/Helper');
App::uses('ExportFormat', 'Tools');

/**
 * View wrapper around the ExportFormat lib so templates can pull the canonical
 * glyph of an export format with $this->ExportFormat->get($key) — or the whole
 * table, for the ones that render every format in a loop, with ->all().
 */
class ExportFormatHelper extends AppHelper
{
    /**
     * @return array see ExportFormat::all()
     */
    public function all()
    {
        return ExportFormat::all();
    }

    /**
     * @param string $format
     * @return array see ExportFormat::get()
     */
    public function get($format)
    {
        return ExportFormat::get($format);
    }

    /**
     * @return array see ExportFormat::fallback()
     */
    public function fallback()
    {
        return ExportFormat::fallback();
    }

    /**
     * The glyph in its tinted tile — the shape both export surfaces draw it in.
     * `.ex-icon` in mainOvermind.css turns `--h` into the ink and the tint.
     *
     * @param string $format
     * @param string $class extra classes on the tile
     * @return string
     */
    public function tile($format, $class = '')
    {
        $meta = ExportFormat::get($format);

        return sprintf(
            '<span class="ex-icon%s" style="--h: %d;"><i class="%s"></i></span>',
            $class === '' ? '' : ' ' . h($class),
            (int)$meta['hue'],
            h($meta['icon'])
        );
    }
}
