# How to contribute

## Coding convention

This plugin follows [CakePHP coding convention](http://book.cakephp.org/2.0/en/contributing/cakephp-coding-conventions.html). 

A PHPCodeSniffer coding standard for CakePHP is available [here](https://github.com/cakephp/cakephp-codesniffer).  
Please make sure the code is valid with `phpcs --standard=CakePHP YOURFILES` before sending a pull request. 

## Testing

### Development workflow

My development workflow make use of grunt watch plugin, that will run phpunit automatically after each file save. Grunt is also used to generate the test coverage.

### Unit Tests

All pull request should not break existing tests. You're more than welcome to write additional tests. There is a grunt task to run the tests :

    grunt caketest
    
Without grunt, just run :

    cake test CakeResque AllCakeResque
    
Or you can also run tests after each file edition :

	grunt watch	

### Test coverage

Use the coverage grunt task to generate code coverage.
    
    grunt coverage
    
Without grunt, use :

	cake test CakeResque AllCakeResque --configuration Test/phpunit.xml
	
Fix the path to phpunit.xml depending on your current directory.
    
The coverage reports is in build/coverage/index.html.

## Documentation

You can also contribute to [website](http://cakeresque.kamisama.me/) documentation.
All files are located in the [doc](https://github.com/kamisama/Cake-Resque/tree/gh-pages/docs) folder, on the [gh-pages](https://github.com/kamisama/Cake-Resque/tree/gh-pages) branche.

There's one folder for each language. As of now, only english and french are available.

Documentation uses the [Markdown Extra(http://michelf.ca/projects/php-markdown/extra/) syntax, mixed with some html.