<?php
App::uses('AppHelper', 'View/Helper');

class IconHelper extends AppHelper
{
    public $helpers = ['FontAwesome', 'Bootstrap'];

    public function icon($icon)
    {
        if (!empty($icon['icons']) || !empty($icon['stacked'])) {
            if (!empty($icon['stacked'])) {
                $icon['icons'] = $icon['stacked'];
            }
            return $this->stackedIcons($icon);
        } else if (!empty($icon['image'])) {
            return $this->image($icon);
        } else if (!empty($icon['html'])) {
            return $this->rawHtml($icon['html']);
        }
        return $this->regularIcon($icon);
    }

    public function regularIcon($icon)
    {
        return $this->Bootstrap->node('i', [
            'class' => h($icon['class'] ?? '') . ' ' .$this->FontAwesome->getClass($icon['icon'] ?? $icon),
            'style' => h($icon['style'] ?? ''),
            'title' => h($icon['title'] ?? null)
        ]);
    }

    public function stackedIcons($icons)
    {
        $options = $icons;
        $icons = $icons['icons'];
        $html = $this->Bootstrap->node('span', [
                'class' => sprintf('fa-stack fa-stack-small %s', h($options['class'] ?? '')),
                'style' => h($options['style'] ?? '')
            ],
            implode('', [
                $this->Bootstrap->node('span', [
                    'class' => sprintf('fas fa-stack-2x fa-%s %s', h($icons[0]['icon'] ?? ''), h($icons[0]['class'] ?? '')),
                    'style' => h($icons[0]['style'] ?? ''),
                ]),
                $this->Bootstrap->node('span', [
                    'class' => sprintf('fas fa-stack-1x fa-%s %s', h($icons[1]['icon'] ?? ''), h($icons[1]['class'] ?? '')),
                    'style' => h($icons[1]['style'] ?? ''),
                ])
            ])
        );
        return $html;
    }

    public function image($image)
    {
        return $this->Bootstrap->node('img', [
            'class' => h($image['class'] ?? ''),
            'style' => h($image['style'] ?? ''),
            'src' => h($image['image'] ?? ''),
            'title' => h($image['title'] ?? null)
        ]);
    }

    public function rawHtml($html)
    {
        return $html;
    }

    /**
     * @param string $countryCode ISO 3166-1 alpha-2 two-letter country code
     * @param string $countryName Full country name for title
     * @return string
     */
    public function countryFlag($countryCode, $countryName = null)
    {
        if (strlen($countryCode) !== 2) {
            return '';
        }

        $output = [];
        foreach (str_split(strtolower($countryCode)) as $letter) {
            $letterCode = ord($letter);
            if ($letterCode < 97 || $letterCode > 122) {
                return ''; // invalid letter
            }
            $output[] = "1f1" . dechex(0xe6 + ($letterCode - 97));
        }

        $baseurl = $this->_View->viewVars['baseurl'];
        $title = __('Flag of %s',  strtoupper($countryName ? h($countryName) : $countryCode));
        return '<img src="' . $baseurl . '/img/flags/' . implode('-', $output) . '.svg" title="' . $title .'" alt="' . $title . '" aria-label="' . $title . '"  style="height: 18px" />';
    }
}
