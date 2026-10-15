<?php
App::uses('AppHelper', 'View/Helper');

/**
 * Icon, colour and label of each kind of MISP record a collection can hold,
 * so every place that names an element's type draws it the same way.
 */
class ElementTypeHelper extends AppHelper
{
    const STYLES = [
        'Event' => [
            'icon' => 'misp-icon misp-icon-event misp-simple',
            'color' => 'var(--bs-event)',
        ],
        'GalaxyCluster' => [
            'icon' => 'misp-icon misp-icon-galaxy misp-simple',
            'color' => 'var(--bs-galaxy)',
        ],
        'Attribute' => [
            'icon' => 'misp-icon misp-icon-attribute misp-simple',
            'color' => 'var(--bs-attribute)',
        ],
        'Object' => [
            'icon' => 'misp-icon misp-icon-object misp-simple',
            'color' => 'var(--bs-object)',
        ],
        'AttributeValue' => [
            'icon' => 'misp-icon misp-icon-value-intelligence misp-simple',
            'color' => 'var(--bs-valueIntelligence)',
        ],
    ];

    /**
     * @return array type => ['icon', 'color', 'ink', 'label']
     */
    public function styles()
    {
        $styles = [];
        foreach (array_keys(self::STYLES) as $type) {
            $styles[$type] = $this->style($type);
        }
        return $styles;
    }

    /**
     * @param string $type
     * @return array
     */
    public function style($type)
    {
        $style = self::STYLES[$type] ?? [
            'icon' => 'fas fa-cube',
            'color' => 'var(--bs-secondary)',
        ];
        return $style + [
            'ink' => '#fff',
            'label' => $this->label($type),
        ];
    }

    /**
     * @param string $type
     * @return string
     */
    public function label($type)
    {
        $labels = [
            'Event' => __('Event'),
            'GalaxyCluster' => __('Galaxy cluster'),
            'Attribute' => __('Attribute'),
            'Object' => __('Object'),
            'AttributeValue' => __('Value'),
        ];
        return $labels[$type] ?? (string)$type;
    }

    /**
     * The type as a chip carrying its icon, followed by its label.
     *
     * @param string $type
     * @return string HTML
     */
    public function badge($type)
    {
        $style = $this->style($type);
        return sprintf(
            '<span class="d-inline-flex align-items-center gap-2 text-nowrap">'
                . '<span class="d-inline-flex align-items-center justify-content-center rounded"'
                    . ' style="width:1.6rem;height:1.6rem;background:%s;color:%s;" aria-hidden="true">'
                    . '<i class="%s"></i>'
                . '</span>'
                . '<span>%s</span>'
            . '</span>',
            $style['color'],
            $style['ink'],
            h($style['icon']),
            h($style['label'])
        );
    }
}
