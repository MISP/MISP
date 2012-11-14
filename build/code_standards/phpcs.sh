#!/bin/sh

#For the moment we use this given we do have Jenkins,
#but not the ssh keys in place for Jenkins to connect to Git.


cd /var/www/cydefsig
rm build/code_standards/result.txt
touch build/code_standards/result.txt
#phpcs --standard=CakePHP app/Config/database.php >>build/code_standards/result.txt

phpcs --standard=CakePHP app/Console/Command/PasswordShell.php >>build/code_standards/result.txt

#phpcs --standard=CakePHP app/Model/AppModel.php >build/code_standards/appmodel.txt
#phpcs --standard=CakePHP app/Model/Attribute.php >build/code_standards/attribute.txt
#phpcs --standard=CakePHP app/Model/Bruteforce.php >build/code_standards/bruteforce.txt
#phpcs --standard=CakePHP app/Model/Correlation.php >build/code_standards/correlation.txt
#phpcs --standard=CakePHP app/Model/Dns.php >build/code_standards/dns.txt
#phpcs --standard=CakePHP app/Model/Event.php >build/code_standards/event.txt
#phpcs --standard=CakePHP app/Model/Server.php >build/code_standards/server.txt
#phpcs --standard=CakePHP app/Model/User.php >build/code_standards/user.txt
#phpcs --standard=CakePHP app/Model/Whitelist.php >build/code_standards/whitelist.txt
phpcs --standard=CakePHP app/Model/ >>build/code_standards/result.txt

phpcs --standard=CakePHP app/Controller/Component/HidsSha1ExportComponent.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/Component/HidsMd5ExportComponent.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/Component/NidsExportComponent.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/Component/SecureAuthComponent.php >>build/code_standards/result.txt
#phpcs --standard=CakePHP app/Controller/Component/ >build/code_standards/component.txt

phpcs --standard=CakePHP app/Controller/AppController.php >>build/code_standards/result.txt	# !!!
phpcs --standard=CakePHP app/Controller/AttributesController.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/EventsController.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/ServersController.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/UsersController.php >>build/code_standards/result.txt
phpcs --standard=CakePHP app/Controller/WhitelistsController.php >>build/code_standards/result.txt

#mkdir build/code_standards/view
phpcs --standard=CakePHP app/View/Attributes/add_attachment.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/add.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/event.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/search.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Attributes/xml/index.ctp >>build/code_standards/result.txt

phpcs --standard=CakePHP app/View/Elements/actions_menu.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Emails/text/body.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Emails/text/new_event.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Errors/error403.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Helper/AppHelper.php >>build/code_standards/result.txt	# !!!
phpcs --standard=CakePHP app/View/Layouts/text/default.ctp >>build/code_standards/result.txt

phpcs --standard=CakePHP app/View/Events/add.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/contact.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/edit.ctp >>build/code_standards/result.txt
#phpcs --standard=CakePHP app/View/Events/event.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/export.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/hids.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/nids.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/text.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/view.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/xml.ctp >>build/code_standards/result.txt
#CHECK  phpcs --standard=CakePHP app/View/Events/xml/add.ctp >>build/code_standards/result.txt
#CHECK  phpcs --standard=CakePHP app/View/Events/xml/edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/xml/index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Events/xml/view.ctp >>build/code_standards/result.txt

#phpcs --standard=CakePHP app/View/Pages/documentation.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Pages/ >>build/code_standards/result.txt

phpcs --standard=CakePHP app/View/Servers/add.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Servers/edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Servers/index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Servers/pull.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Servers/push.ctp >>build/code_standards/result.txt

phpcs --standard=CakePHP app/View/Users/admin_add.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/admin_edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/admin_index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/admin_view.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/login.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/memberslist.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/news.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/terms.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Users/view.ctp >>build/code_standards/result.txt

phpcs --standard=CakePHP app/View/Whitelists/admin_add.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Whitelists/admin_edit.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Whitelists/admin_index.ctp >>build/code_standards/result.txt
phpcs --standard=CakePHP app/View/Whitelists/admin_view.ctp >>build/code_standards/result.txt

#phpcs --standard=CakePHP app/Plugin/SysLogLogable/Model/Behavior/SysLogLogableBehavior.php >>build/code_standards/result.txt
