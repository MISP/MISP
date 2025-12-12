<?php

/**
 * BetaUiHelper - Helper class for managing beta UI opt-in functionality
 * 
 * This helper provides utilities for serving different UI elements, templates,
 * and stylesheets to users who have opted into the beta UI experience.
 * 
 * Usage:
 * - In controllers: Use helper methods to select appropriate views
 * - In views: Use helper methods to conditionally render elements
 * - In layouts: Use helper methods to load beta-specific stylesheets
 */
class BetaUiHelper
{
    /**
     * Get the appropriate view file path based on beta UI setting
     * 
     * This method checks if a beta version of a view exists and returns
     * the appropriate path based on the user's beta UI preference.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @param string $viewPath The standard view path (e.g., 'Events/index')
     * @return string The view path to use
     * 
     * Example:
     *   $viewPath = BetaUiHelper::getViewPath($uiBetaEnabled, 'Events/index');
     *   // Returns 'Events/index_beta' if beta enabled and file exists
     *   // Otherwise returns 'Events/index'
     */
    public static function getViewPath($uiBetaEnabled, $viewPath)
    {
        if (!$uiBetaEnabled) {
            return $viewPath;
        }
        
        $betaViewPath = $viewPath . '_beta';
        $viewFile = APP . 'View' . DS . str_replace('/', DS, $betaViewPath) . '.ctp';
        
        if (file_exists($viewFile) && self::__isSafePath($viewFile, APP . 'View')) {
            return $betaViewPath;
        }
        
        return $viewPath;
    }
    
    /**
     * Get the appropriate element path based on beta UI setting
     * 
     * This method checks if a beta version of an element exists and returns
     * the appropriate path based on the user's beta UI preference.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @param string $elementPath The standard element path (e.g., 'global_menu')
     * @return string The element path to use
     * 
     * Example:
     *   $elementPath = BetaUiHelper::getElementPath($uiBetaEnabled, 'global_menu');
     *   // Returns 'global_menu_beta' if beta enabled and file exists
     *   // Otherwise returns 'global_menu'
     */
    public static function getElementPath($uiBetaEnabled, $elementPath)
    {
        if (!$uiBetaEnabled) {
            return $elementPath;
        }
        
        $betaElementPath = $elementPath . '_beta';
        $elementFile = APP . 'View' . DS . 'Elements' . DS . str_replace('/', DS, $betaElementPath) . '.ctp';
        
        if (file_exists($elementFile) && self::__isSafePath($elementFile, APP . 'View' . DS . 'Elements')) {
            return $betaElementPath;
        }
        
        return $elementPath;
    }
    
    /**
     * Get the appropriate layout path based on beta UI setting
     * 
     * This method checks if a beta version of a layout exists and returns
     * the appropriate path based on the user's beta UI preference.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @param string $layoutPath The standard layout path (e.g., 'default')
     * @return string The layout path to use
     * 
     * Example:
     *   $layoutPath = BetaUiHelper::getLayoutPath($uiBetaEnabled, 'default');
     *   // Returns 'default_beta' if beta enabled and file exists
     *   // Otherwise returns 'default'
     */
    public static function getLayoutPath($uiBetaEnabled, $layoutPath)
    {
        if (!$uiBetaEnabled) {
            return $layoutPath;
        }
        
        $betaLayoutPath = $layoutPath . '_beta';
        $layoutFile = APP . 'View' . DS . 'Layouts' . DS . $betaLayoutPath . '.ctp';
        
        if (file_exists($layoutFile) && self::__isSafePath($layoutFile, APP . 'View' . DS . 'Layouts')) {
            return $betaLayoutPath;
        }
        
        return $layoutPath;
    }
    
    /**
     * Get beta-specific CSS files to load
     * 
     * This method returns an array of CSS files that should be loaded
     * when beta UI is enabled. These files will override or supplement
     * the standard CSS.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @return array Array of CSS file names (without .css extension)
     * 
     * Example:
     *   $betaCss = BetaUiHelper::getBetaCssFiles($uiBetaEnabled);
     *   // Returns ['main-beta', 'components-beta'] if beta enabled
     *   // Otherwise returns []
     */
    public static function getBetaCssFiles($uiBetaEnabled)
    {
        if (!$uiBetaEnabled) {
            return [];
        }
        
        $betaCssFiles = [];
        $cssDir = APP . 'webroot' . DS . 'css' . DS;
        
        $potentialBetaFiles = [
            'main-beta',
            'components-beta',
            'layout-beta',
            'theme-beta'
        ];
        
        foreach ($potentialBetaFiles as $file) {
            if (file_exists($cssDir . $file . '.css')) {
                $betaCssFiles[] = $file;
            }
        }
        
        return $betaCssFiles;
    }
    
    /**
     * Check if a specific beta feature is enabled
     * 
     * This method allows for granular control of beta features beyond
     * just the global beta UI opt-in. Features can be controlled via
     * configuration or additional user settings.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @param string $featureName The name of the feature to check
     * @return bool Whether the feature is enabled
     * 
     * Example:
     *   if (BetaUiHelper::isFeatureEnabled($uiBetaEnabled, 'new_event_view')) {
     *       // Use new event view
     *   }
     */
    public static function isFeatureEnabled($uiBetaEnabled, $featureName)
    {
        if (!$uiBetaEnabled) {
            return false;
        }
        
        $enabledFeatures = Configure::read('MISP.beta_ui_features');
        if (empty($enabledFeatures)) {
            return true;
        }
        
        return in_array($featureName, $enabledFeatures);
    }
    
    /**
     * Get a CSS class modifier for beta UI elements
     * 
     * This method returns a CSS class suffix that can be used to apply
     * beta-specific styling to elements without creating entirely new templates.
     * 
     * @param bool $uiBetaEnabled Whether the user has beta UI enabled
     * @param string $prefix Optional prefix for the class (default: '')
     * @return string CSS class modifier
     * 
     * Example:
     *   <div class="event-list<?= BetaUiHelper::getCssModifier($uiBetaEnabled) ?>">
     *   // Renders as: <div class="event-list event-list--beta">
     */
    public static function getCssModifier($uiBetaEnabled, $prefix = '')
    {
        if (!$uiBetaEnabled) {
            return '';
        }
        
        return $prefix . ' ' . $prefix . '--beta';
    }

    /**
     * Check if a path is safe (within the expected base directory)
     * 
     * @param string $path The full path to check
     * @param string $baseDir The expected base directory
     * @return bool True if path is safe, false otherwise
     */
    private static function __isSafePath($path, $baseDir)
    {
        $realPath = realpath($path);
        $realBaseDir = realpath($baseDir);

        if ($realPath === false || $realBaseDir === false) {
            return false;
        }

        // Ensure base directory has trailing separator for strict prefix check
        if (substr($realBaseDir, -1) !== DS) {
            $realBaseDir .= DS;
        }

        return strpos($realPath, $realBaseDir) === 0;
    }
}
