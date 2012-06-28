INSTALLATION INSTRUCTIONS
-------------------------
If on Ubuntu, besides the DocumentRoot,
you have to change the AllowOverride from None to All as well.

	DocumentRoot /var/www/cydefsig/app/webroot/
	<Directory />
		Options FollowSymLinks
		AllowOverride All
	</Directory>
	<Directory /var/www/>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride All
		Order allow,deny
		allow from all
	</Directory>

Find the original below, for reference.

	DocumentRoot /var/www

	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory /var/www/>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>

Now /etc/init.d/apache2 restart
and you are done, and now able to use the application.