VIRTUAL HOST INSTRUCTION
------------------------

CyDefSIG is able to run in an Apache virtual host setup.
This takes 2 variables, the hostname and CyDefSIG directory.
To this one must enter the hostname in /etc/hosts
and create an Apache config in apache2/sites-available.

Say we have a hostname cydefsig2.local.net and
CyDefSIG installed in /var/www/second_instance/cydefsig,
we will add to /etc/hosts:

127.0.1.1       cydefsig2.local.net

And create a file /etc/apache2/sites-available/<second_instance_name>
containing:

<VirtualHost *:80>
        ServerAdmin webmaster@example.com
        ServerName  cydefsig2.local.net
        ServerAlias mysite

        # Indexes + Directory Root.
        DirectoryIndex index.php
        DocumentRoot /var/www/second_instance/cydefsig/app/webroot
</VirtualHost>