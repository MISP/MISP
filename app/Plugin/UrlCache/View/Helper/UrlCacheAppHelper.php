<?php

/*
* App Helper url caching
* Copyright (c) 2009 Matt Curry
* www.PseudoCoder.com
* http://github.com/mcurry/cakephp/tree/master/snippets/app_helper_url
* http://www.pseudocoder.com/archives/2009/02/27/how-to-save-half-a-second-on-every-cakephp-requestand-maintain-reverse-routing
*
* @author		Matt Curry <matt@pseudocoder.com>
* @author		José Lorenzo Rodríguez
* @license		MIT
*
* @modified	Mark Scherer
*/

App::uses('Helper', 'View');
App::uses('Inflector', 'Utility');
App::uses('UrlCacheManager', 'UrlCache.Routing');

class UrlCacheAppHelper extends Helper {

	/**
	 * This function is responsible for setting up the Url cache before the application starts generating urls in views
	 *
	 * @return void
	 */
	function beforeRender($viewFile) {
		if (!Configure::read('UrlCache.active') || Configure::read('UrlCache.runtime.beforeRender')) {
			return;
		}

		# todo: maybe lazy load with HtmlHelper::url()?
		UrlCacheManager::init($this->_View);
		Configure::write('UrlCache.runtime.beforeRender', true);
	}

	/**
	 * This method will store the current generated urls into a persistent cache for next use
	 *
	 * @return void
	 */
	function afterLayout($layoutFile) {
		if (!Configure::read('UrlCache.active') || Configure::read('UrlCache.runtime.afterLayout')) {
			return;
		}

		UrlCacheManager::finalize();
		Configure::write('UrlCache.runtime.afterLayout', true);
	}

	/**
	 * Intercepts the parent url function to first look if the cache was already generated for the same params
	 *
	 * @param mixed $url url to generate using cakephp array syntax
	 * @param boolean $full wheter to generate a full url or not (http scheme)
	 * @return string
	 * @see Helper::url()
	 */
	function url($url = null, $full = false) {
		if (Configure::read('UrlCache.active')) {
			if ($cachedUrl = UrlCacheManager::get($url, $full)) {
				return $cachedUrl;
			}
		}

		$routerUrl = h(Router::url($url, $full));
		if (Configure::read('UrlCache.active')) {
			UrlCacheManager::set($routerUrl);
		}
		return $routerUrl;
	}

}
