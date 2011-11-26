# Recaptcha Plugin for CakePHP #

The Recaptcha plugin for CakePHP provides spam protection in an easy use helper.

## Usage ##

To use the recaptcha plugin its required to include the following two lines in your `/app/config/bootstrap.php` file.

	Configure::write('Recaptcha.publicKey', 'your-public-api-key');
	Configure::write('Recaptcha.privateKey', 'your-private-api-key');

Don't forget to replace the placeholder text with your actual keys!

Keys can be obtained for free from the [Recaptcha website](http://www.google.com/recaptcha).

Controllers that will be using recaptcha require the Recaptcha Component to be included. Through inclusion of the component, the helper is automatically made available to your views.

In the view simply call the helpers `display()` method to render the recaptcha input:

	echo $this->Recaptcha->display();

To check the result simply do something like this in your controller:

	if (!empty($this->data)) {
		if ($this->Recaptcha->verify()) {
			// do something, save you data, login, whatever
		} else {
			// display the raw API error
			$this->Session->setFlash($this->Recaptcha->error);
		}
	}

## Requirements ##

* PHP version: PHP 5.2+
* CakePHP version: Cakephp 1.3 Stable

## Support ##

For support and feature request, please visit the [Recaptcha Plugin Support Site](http://cakedc.lighthouseapp.com/projects/60546-recaptcha-plugin/).

For more information about our Professional CakePHP Services please visit the [Cake Development Corporation website](http://cakedc.com).

## License ##

Copyright 2009-2010, [Cake Development Corporation](http://cakedc.com)

Licensed under [The MIT License](http://www.opensource.org/licenses/mit-license.php)<br/>
Redistributions of files must retain the above copyright notice.

## Copyright ###

Copyright 2009-2010<br/>
[Cake Development Corporation](http://cakedc.com)<br/>
1785 E. Sahara Avenue, Suite 490-423<br/>
Las Vegas, Nevada 89104<br/>
http://cakedc.com<br/>
