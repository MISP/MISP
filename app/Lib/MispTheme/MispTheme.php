<?php
class MispTheme
{
    public $name;
    public $label;
    public $description;
    public $active;
    public $hideFromUsers;

    public function __construct($name, $label = '', $description = '', $active = false, $hideFromUsers = false)
    {
        $this->name = $name;
        $this->label = !empty($label) ? $label : $name . ' UI';
        $this->description = $description;
        $this->active = $active;
        $this->hideFromUsers = $hideFromUsers;
    }

    /**
     * Get all available themes as MispTheme objects
     *
     * @param string $currentActiveTheme The name of the currently active theme
     * @param bool $showHiddenThemes Whether to include hidden themes (e.g. for developers)
     * @return MispTheme[]
     */
    public static function getAvailableThemes($currentActiveTheme = 'Default', $showHiddenThemes = false)
    {
        $userSetting = ClassRegistry::init('UserSetting');
        $themeNames = $userSetting::VALID_SETTINGS['ui_theme']['options'];

        $themes = [];
        foreach ($themeNames as $name) {
            $label = '';
            $description = '';
            $hideFromUsers = false;

            if ($name === 'Default') {
                $label = __('Default UI');
                $description = __('The classic MISP interface.');
            } else {
                $themeFile = APP . 'View' . DS . 'Themed' . DS . $name . DS . 'theme.php';
                if (file_exists($themeFile)) {
                    $themeConfig = include $themeFile;
                    $label = !empty($themeConfig['label']) ? $themeConfig['label'] : '';
                    $description = !empty($themeConfig['description']) ? $themeConfig['description'] : '';
                    $hideFromUsers = !empty($themeConfig['hide_from_users']) ? (bool)$themeConfig['hide_from_users'] : false;
                }
            }

            if ($hideFromUsers && !$showHiddenThemes && $name !== $currentActiveTheme) {
                continue;
            }
            $themes[] = new MispTheme($name, $label, $description, $name === $currentActiveTheme, $hideFromUsers);
        }
        return $themes;
    }

    const DEFAULT_BOOTSTRAP_THEME = 'overmind';

    const BOOTSTRAP_THEME_MODES = ['light', 'dark', 'both'];

    /** @var array|null */
    private static $bootstrapThemes = null;

    /**
     * The Bootstrap stylesheets built by tools/bootstrap-themes, discovered from
     * the metadata file the build writes beside each one.
     *
     * @return array name => ['name', 'label', 'description', 'mode', 'hide_from_users']
     */
    public static function getBootstrapThemes()
    {
        if (self::$bootstrapThemes !== null) {
            return self::$bootstrapThemes;
        }
        $themes = [];
        $dir = WWW_ROOT . 'css' . DS . 'themes' . DS;
        foreach (glob($dir . '*.json') ?: [] as $file) {
            $name = basename($file, '.json');
            if (!self::isBootstrapThemeName($name) || !is_file($dir . $name . '.min.css')) {
                continue;
            }
            $meta = json_decode(file_get_contents($file), true);
            if (!is_array($meta) || !in_array($meta['mode'] ?? null, self::BOOTSTRAP_THEME_MODES, true)) {
                continue;
            }
            $themes[$name] = [
                'name' => $name,
                'label' => !empty($meta['label']) ? $meta['label'] : $name,
                'description' => $meta['description'] ?? '',
                'mode' => $meta['mode'],
                'hide_from_users' => !empty($meta['hide_from_users']),
            ];
        }
        ksort($themes);
        return self::$bootstrapThemes = $themes;
    }

    /**
     * @param mixed $name
     * @return bool
     */
    public static function isBootstrapTheme($name)
    {
        return self::isBootstrapThemeName($name) && isset(self::getBootstrapThemes()[$name]);
    }

    /**
     * The Bootstrap theme a page renders with: the user's choice, else the
     * instance default, else Overmind. A name that no longer resolves to a built
     * theme falls through to the next.
     *
     * @param array|null $user
     * @return array The theme's metadata plus 'css', its path under css/
     */
    public static function bootstrapTheme($user = null)
    {
        $candidates = [];
        if (!empty($user['id'])) {
            $candidates[] = ClassRegistry::init('UserSetting')->getValueForUser($user['id'], 'ui_bootstrap_theme');
        }
        $candidates[] = Configure::read('MISP.default_bootstrap_theme');
        $candidates[] = self::DEFAULT_BOOTSTRAP_THEME;

        $themes = self::getBootstrapThemes();
        foreach ($candidates as $name) {
            if (self::isBootstrapThemeName($name) && isset($themes[$name])) {
                return $themes[$name] + ['css' => 'themes/' . $name . '.min'];
            }
        }
        // No build output at all: keep the page styled.
        return [
            'name' => self::DEFAULT_BOOTSTRAP_THEME,
            'label' => 'Overmind',
            'description' => '',
            'mode' => 'both',
            'hide_from_users' => false,
            'css' => 'themes/' . self::DEFAULT_BOOTSTRAP_THEME . '.min',
        ];
    }

    /**
     * @param mixed $name
     * @return bool
     */
    private static function isBootstrapThemeName($name)
    {
        return is_string($name) && preg_match('/^[a-z0-9][a-z0-9_-]*$/', $name) === 1;
    }
}
