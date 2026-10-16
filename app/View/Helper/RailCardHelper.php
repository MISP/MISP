<?php
App::uses('AppHelper', 'View/Helper');

/**
 * Renders the rail cards built by Lib/Tools/RailCards into the right column
 * of genericElementsBS5/Layout/view_layout.
 */
class RailCardHelper extends AppHelper
{
    const PALETTE = ['blue', 'pink', 'teal', 'indigo', 'yellow', 'cyan', 'orange', 'purple'];

    const TONES = ['ok', 'info', 'warn', 'danger', 'muted'];

    const STATE_ICONS = [
        'ok' => 'fas fa-check',
        'info' => 'fas fa-info',
        'warn' => 'fas fa-exclamation',
        'danger' => 'fas fa-xmark',
        'muted' => 'fas fa-minus',
    ];

    /**
     * view_layout column entries for the cards named in $ids, in that order.
     * A card missing from $cards is skipped, a slot becomes a lazy entry.
     *
     * @param array $cards card id => card or slot
     * @param array $ids
     * @param string $tab the tab the rail belongs to
     * @return array
     */
    public function rail(array $cards, array $ids, $tab)
    {
        $this->addStylesheet();
        $entries = [];
        foreach ($ids as $id) {
            if (empty($cards[$id])) {
                continue;
            }
            $card = $cards[$id];
            if (isset($card['url'])) {
                $entries[] = [
                    'ajax' => $this->href($card['url']),
                    'share' => true,
                    'placeholder' => [
                        'element' => 'genericElementsBS5/Rail/placeholder',
                        'params' => ['card' => $card],
                    ],
                ];
            } else {
                $entries[] = [
                    'element' => 'genericElementsBS5/Rail/card',
                    'params' => ['card' => $card, 'tab' => $tab],
                ];
            }
        }
        return $entries;
    }

    /**
     * Into the layout's head rather than beside a card: a lazy card's
     * placeholder is replaced, and anything linked inside it goes too.
     *
     * @return void
     */
    private function addStylesheet()
    {
        $css = (array)$this->_View->get('additionalCss');
        if (!in_array('rail-cards', $css, true)) {
            $css[] = 'rail-cards';
            $this->_View->set('additionalCss', $css);
        }
    }

    /**
     * @param array $card
     * @return bool
     */
    public function isEmpty(array $card)
    {
        switch ($card['shape']) {
            case 'inventory':
                return empty($card['groups']) || empty($card['total']['count']);
            case 'activity':
                return !array_filter(array_column($card['series'], 'count'));
            case 'list':
                return empty($card['rows']);
            case 'usage':
                return empty($card['headline']['count']);
            case 'facts':
                return empty($this->factRows($card));
        }
        return false;
    }

    /**
     * @param array $card
     * @return array the rows that have at least one value
     */
    public function factRows(array $card)
    {
        return array_values(array_filter($card['rows'], function ($row) {
            return !empty($row['values']);
        }));
    }

    /**
     * The header link, unless it points at the tab the card sits on.
     *
     * @param array $card
     * @param string|null $tab
     * @return array|null
     */
    public function headerLink(array $card, $tab)
    {
        if (empty($card['link']) || $card['link']['href'] === '#tab-' . $tab) {
            return null;
        }
        return $card['link'];
    }

    /**
     * @param string $href app-relative, #tab-… or absolute
     * @return string
     */
    public function href($href)
    {
        if (is_string($href) && strpos($href, '/') === 0 && strpos($href, '//') !== 0) {
            return $this->_View->get('baseurl') . $href;
        }
        return (string)$href;
    }

    /**
     * An anchor, or a span when there is no href. $content is HTML.
     *
     * @param string|null $href
     * @param string $class
     * @param string $content
     * @param string|null $title
     * @param string|null $style
     * @param array $extra more attributes, name => value
     * @return string
     */
    public function link($href, $class, $content, $title = null, $style = null, array $extra = [])
    {
        $attrs = ' class="' . h($class) . '"'
            . ($title === null ? '' : ' title="' . h($title) . '"')
            . ($style === null ? '' : ' style="' . h($style) . '"');
        foreach ($extra as $name => $value) {
            $attrs .= ' ' . h($name) . '="' . h($value) . '"';
        }
        if (empty($href)) {
            return '<span' . $attrs . '>' . $content . '</span>';
        }
        if (preg_match('#^https?://#i', $href)) {
            $attrs .= ' target="_blank" rel="noopener noreferrer"';
        }
        return '<a href="' . h($this->href($href)) . '"' . $attrs . '>' . $content . '</a>';
    }

    /**
     * @param mixed $value
     * @return string escaped
     */
    public function num($value)
    {
        if (is_int($value) || is_float($value)) {
            return h(number_format($value));
        }
        return h((string)$value);
    }

    /**
     * @param float $share 0..1
     * @return string
     */
    public function pct($share)
    {
        $p = $share * 100;
        if ($p >= 10 || $p == 0) {
            return round($p) . '%';
        }
        if ($p < 0.1) {
            return '<0.1%';
        }
        return number_format($p, 1) . '%';
    }

    /**
     * @param string|null $tone
     * @param string $prefix
     * @return string a leading space and the class, or nothing
     */
    public function toneClass($tone, $prefix = 'rcard-t-')
    {
        return in_array($tone, self::TONES, true) ? ' ' . $prefix . $tone : '';
    }

    /**
     * One paint per part: its tone, its entity colour, or the next palette
     * colour, so neighbouring parts never share one.
     *
     * @param array $parts each with 'tone'?, 'color'?, 'other'?
     * @param string|null $avoid a palette colour already used next to them
     * @return array each ['class', 'color' => string|null]
     */
    public function paints(array $parts, $avoid = null)
    {
        $k = 0;
        $paints = [];
        $palette = self::PALETTE;
        foreach ($parts as $part) {
            if (!empty($part['other'])) {
                $paints[] = ['class' => 'rcard-other', 'color' => null];
            } else if (in_array($part['tone'] ?? null, self::TONES, true)) {
                $paints[] = ['class' => 'rcard-fill-' . $part['tone'], 'color' => null];
            } else if (!empty($part['color']) && preg_match('/^[A-Za-z][\w-]*$/', $part['color'])) {
                $paints[] = ['class' => 'rcard-c', 'color' => $part['color']];
            } else {
                $colour = $palette[$k++ % count($palette)];
                if ($colour === $avoid) {
                    $colour = $palette[$k++ % count($palette)];
                }
                $paints[] = ['class' => 'rcard-c', 'color' => $colour];
            }
        }
        return $paints;
    }

    /**
     * class and style attributes for a painted element.
     *
     * @param array $paint from paints()
     * @param string $class
     * @param string $style extra declarations
     * @return string
     */
    public function painted(array $paint, $class, $style = '')
    {
        if ($paint['color'] !== null) {
            $style .= '--rcard-c: var(--bs-' . $paint['color'] . ');';
        }
        return ' class="' . h($class . ' ' . $paint['class']) . '"'
            . ($style === '' ? '' : ' style="' . h($style) . '"');
    }

    /**
     * @param array $paint
     * @param string $class
     * @return string
     */
    public function swatch(array $paint, $class = '')
    {
        return '<span' . $this->painted($paint, trim('rcard-swatch ' . $class)) . ' aria-hidden="true"></span>';
    }

    /**
     * A bar split in proportion to each part's count.
     *
     * @param array $parts each with 'label', 'count'
     * @param string $class
     * @param array $paints from paints()
     * @return string
     */
    public function stack(array $parts, $class, array $paints)
    {
        if (!array_sum(array_column($parts, 'count'))) {
            return '';
        }
        $label = implode(', ', array_map(function ($part) {
            return $part['label'] . ' ' . number_format($part['count']);
        }, $parts));
        $html = '<div class="rcard-stack ' . h($class) . '" role="img" aria-label="' . h($label) . '">';
        foreach ($parts as $i => $part) {
            if (!$part['count']) {
                continue;
            }
            $html .= '<span' . $this->painted($paints[$i], 'rcard-seg', 'flex-grow:' . (int)$part['count'] . ';')
                . ' title="' . h($part['label'] . ': ' . number_format($part['count'])) . '"></span>';
        }
        return $html . '</div>';
    }

    /**
     * @param int $count
     * @param string|null $label
     * @param string|null $context
     * @return string
     */
    public function figure($count, $label, $context = null)
    {
        return '<div class="rcard-figure">'
            . '<span class="rcard-num">' . $this->num($count) . '</span>'
            . ($label ? '<span class="rcard-num-label">' . h($label) . '</span>' : '')
            . ($context ? '<span class="rcard-num-context">' . h($context) . '</span>' : '')
            . '</div>';
    }

    /**
     * @param array|null $last ['ts', 'label', 'ago']
     * @return string
     */
    public function last($last)
    {
        if (empty($last)) {
            return '';
        }
        return '<div class="rcard-last">'
            . '<span class="rcard-last-label">' . h($last['label']) . '</span>'
            . '<span class="rcard-last-ago" title="' . h(gmdate('Y-m-d H:i', $last['ts']) . ' UTC') . '">'
            . h($last['ago']) . '</span>'
            . '</div>';
    }

    /**
     * A "+N" chip, linking where the card's header link goes.
     *
     * @param int $more
     * @param array $card
     * @param string|null $tab
     * @param string $prefix HTML before the label
     * @return string
     */
    public function moreChip($more, array $card, $tab, $prefix = '')
    {
        if (empty($more)) {
            return '';
        }
        $link = $this->headerLink($card, $tab);
        return $this->link(
            $link ? $link['href'] : null,
            'rcard-chip rcard-chip-more',
            $prefix . '+' . $this->num((int)$more),
            $link ? $link['label'] : null
        );
    }

    /**
     * @param float $fraction 0..1
     * @param string|null $tone
     * @param string $title
     * @return string
     */
    public function meter($fraction, $tone, $title)
    {
        $width = max(0, min(1, $fraction)) * 100;
        if ($width > 0 && $width < 1.5) {
            $width = 1.5;
        }
        $fill = $this->toneClass($tone, 'rcard-fill-');
        return '<div class="rcard-meter" title="' . h($title) . '">'
            . '<span class="rcard-meter-fill' . $fill . '" style="width:' . round($width, 2) . '%"></span>'
            . '</div>';
    }

    /**
     * @param string|null $icon full class attribute
     * @param string $class
     * @return string
     */
    public function icon($icon, $class = 'rcard-ico')
    {
        return empty($icon) ? '' : '<i class="' . h($icon . ' ' . $class) . '" aria-hidden="true"></i>';
    }
}
