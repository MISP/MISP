<?php
/**
 * Client SSL Certificate Authentication component
 *
 * Authorizes users based on their SSL credentials.
 *
 * Copyright (c) FIRST.Org, Inc. (https://first.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @author        Guilherme Capilé, Tecnodesign (https://tecnodz.com)
 * @copyright     Copyright (c) FIRST.Org, Inc. (https://first.org)
 * @link          http://github.com/FIRSTdotorg/cakephp-CertAuth
 * @package       CertAuth.Certificate
 * @license       http://www.opensource.org/licenses/mit-license.php MIT License
 */
App::uses('AuthComponent', 'Controller/Component');
App::uses('BaseAuthenticate', 'Controller/Component/Auth');

class CertificateAuthenticate extends BaseAuthenticate
{
	/**
	 * Holds the certificate issuer information (available at SSL_CLIENT_I_DN)
	 *
	 * @var array
	 */
	protected static $ca;

	/**
	 * Holds the certificate user information (available at SSL_CLIENT_S_DN)
	 *
	 * @var array
	 */
	protected static $client;

	/**
	 * Holds the user information
	 *
	 * @var array
	 */
	protected static $user;

	/**
	 * Class constructor.
	 *
	 * This should only be called once per request, so it doesn't need to store values in
	 * the instance. Simply checks if the certificate is valid (against configured valid issuers)
	 * and returns the user information encoded.
	 */
	public function __construct()
	{
		self::$ca = self::$client = false;

		if (isset($_SERVER['SSL_CLIENT_I_DN'])) {
			$CA = self::parse($_SERVER['SSL_CLIENT_I_DN'], Configure::read('CertAuth.mapCa'));
			// only valid CAs, if this was configured
			if ($ca=Configure::read('CertAuth.ca')) {
				$k = Configure::read('CertAuth.caId');
				if (!$k) $k = 'CN';
				$id = (isset($CA[$k]))?($CA[$k]):(false);

				if (!$id) {
					$CA = false;
				} else if (is_array($ca)) {
					if (!in_array($id, $ca)) $CA = false;
				} else if ($ca!=$id) {
					$CA = false;
				}
				unset($id, $k);
			}
			self::$ca = $CA;
			unset($CA, $ca);
		}

		if (self::$ca) {
			$map = Configure::read('CertAuth.map');
			if(isset($_SERVER['SSL_CLIENT_S_DN'])) {
				self::$client = self::parse($_SERVER['SSL_CLIENT_S_DN'], $map);
			} else {
				self::$client = array();
			}
			foreach($map as $n=>$d) {
				if(isset($_SERVER[$n])) {
					self::$client[$d] = $_SERVER[$n];
				}
				unset($map[$n], $n, $d);
			}
			unset($map);
			if(!self::$client) {
				self::$client = false;
			}
		}
	}

	/**
	 * Parse certificate extensions
	 *
	 * @TODO    this should properly address the RFC
	 * @param   string            $s    text to be parsed
	 * @param   (optional) array  $map  array of mapping extension to User fields
	 * @return  array             parsed values
	 */
	private static function parse($s, $map=null)
	{
		$r=array();
		if (preg_match_all('#(^/?|\/|\,)([a-zA-Z]+)\=([^\/\,]+)#', $s, $m)) {
			foreach ($m[2] as $i=>$k) {
				if ($map) {
					if (isset($map[$k])) {
						$k = $map[$k];
					} else {
						$k = null;
					}
				}
				if ($k) {
					$v = $m[3][$i];
					$r[$k] = $v;
				}
				unset($m[0][$i], $m[1][$i], $m[2][$i], $m[3][$i], $k, $v, $i);
			}
		}
		return $r;
	}

	// to enable stateless authentication
	public function getUser(CakeRequest $request)
	{
		if (empty(self::$user)) {
			if (self::$client) {
				self::$user = self::$client;
				// If $sync is true, allow the creation of the user from the certificate
				$sync = Configure::read('CertAuth.syncUser');
				$url = Configure::read('CertAuth.restApi.url');
				if ($sync && $url) {
					if (!self::getRestUser()) return false;
				}

				// find and fill user with model
				$userModelKey = empty(Configure::read('CertAuth.userModelKey')) ? 'email' : Configure::read('CertAuth.userModelKey');
				$userDefaults = Configure::read('CertAuth.userDefaults');
				$this->User = ClassRegistry::init('User');
				if (!empty(self::$user[$userModelKey])) {
					$existingUser = $this->User->find('first', array(
						'conditions' => array($userModelKey => self::$user[$userModelKey]),
						'recursive' => false
					));
				}
				if ($existingUser) {
					if ($sync) {
						if (!isset(self::$user['org_id']) && isset(self::$user['org'])) {
							self::$user['org_id'] = $this->User->Organisation->createOrgFromName(self::$user['org'], $existingUser['User']['id'], true);
							// reset user defaults in case it's a different org_id
							if (self::$user['org_id'] && $existingUser['User']['org_id'] != self::$user['org_id']) {
								if ($userDefaults && is_array($userDefaults)) {
									self::$user = array_merge($userDefaults + self::$user);
								}
							}
							unset(self::$user['org']);
						}
						$write = array();
						foreach (self::$user as $k => $v) {
							if (isset($existingUser['User'][$k]) && trim($existingUser['User'][$k]) != trim($v)) {
								$write[] = $k;
								$existingUser['User'][$k] = trim($v);
							}
						}
						if (!empty($write) && !$this->User->save($existingUser['User'], true, $write)) {
							CakeLog::write('alert', 'Could not update model at database with RestAPI data.');
						}
					}
					self::$user = $this->User->getAuthUser($existingUser['User']['id']);
					if (isset(self::$user['gpgkey'])) unset(self::$user['gpgkey']);
				} else if ($sync && !empty(self::$user)) {
					$org = isset(self::$client['org']) ? self::$client['org'] : null;
					if ($org == null) return false;
					if (!isset(self::$user['org_id']) && isset(self::$user['org'])) {
						self::$user['org_id'] = $this->User->Organisation->createOrgFromName($org, 0, true);
						unset(self::$user['org']);
					}
					if ($userDefaults && is_array($userDefaults)) {
						self::$user = array_merge(self::$user, $userDefaults);
					}
					$this->User->create();
					if ($this->User->save(self::$user)) {
						$id = $this->User->id;
						self::$user = $this->User->getAuthUser($id);
						if (isset(self::$user['gpgkey'])) unset(self::$user['gpgkey']);
					} else {
						CakeLog::write('alert', 'Could not insert model at database from RestAPI data. Reason: ' . json_encode($this->User->validationErrors));
					}
				} else {
					// No match -- User doesn't exist !!!
					self::$user = false;
				}
			}
		}
		return self::$user;
	}

	// to enable stateless authentication
	public function authenticate(CakeRequest $request, CakeResponse $response)
	{
		return self::getUser($request);
	}

	/**
	 * Fetches user information from external REST API
	 *
	 * Valid options (should be configured under CertAuth.restApi):
	 *
	 * @param   (optional) array  $options  API configuration
	 *  url     (string) Where to fetch information from
	 *  headers (array)  list of additional headers to be used, reserved for authentication tokens
	 *  params  (array)  mapping of additional params to be included at the url, uses $user values
	 *  map     (array)  mapping of the return values to be added to the self::$user
	 * @return  array    updated user object
	 */
	public function getRestUser($options=null, $user=null)
	{
		if (is_null($options)) {
			$options = Configure::read('CertAuth.restApi');
		}
		if (!is_null($user)) {
			self::$user = $user;
		}

		if (!isset($options['url'])) {
			return null;
		}

		// Create a stream
		$req = array(
			'http'=>array(
				'method'=>'GET',
				'header'=>"Accept: application/json\r\n"
			),
		);
		if (isset($options['headers'])) {
			foreach ($options['headers'] as $k=>$v) {
				if (is_int($k)) {
					$req['header'] .= "{$v}\r\n";
				} else {
					$req['header'] .= "{$k}: {$v}\r\n";
				}
				unset($k, $v);
			}
		}

		$url = $options['url'];
		if (isset($options['param'])) {
			foreach ($options['param'] as $k=>$v) {
				if (isset(self::$user[$v])) {
					$url .= ((strpos($url, '?'))?('&'):('?'))
						. $k . '=' . urlencode(self::$user[$v]);
				}
				unset($k, $v);
			}
		}
		$ctx = stream_context_create($req);
		$a   = file_get_contents($url, false, $ctx);
		if (!$a) return null;

		$A = json_decode($a, true);
		if (!isset($A['data'][0])) {
			self::$user = false;
		} else if (isset($options['map'])) {
			foreach ($options['map'] as $k=>$v) {
				if (isset($A['data'][0][$k])) {
					self::$user[$v] = $A['data'][0][$k];
				}
				unset($k, $v);
			}
		}

		return self::$user;
	}

	protected static $instance;

	public static function ca()
	{
		if (is_null(self::$ca)) new CertificateAuthenticate();
		return self::$ca;
	}

	public static function client()
	{
		if (is_null(self::$client)) new CertificateAuthenticate();
		return self::$client;
	}

}
