#!/bin/sh

#For the moment we use this given we do have Jenkins,
#but not the ssh keys in place for Jenkins to connect to Git.

RESULTFILE=build/code_standards/result.txt

cd /var/www/cydefsig
rm ${RESULTFILE}
touch ${RESULTFILE}
#phpcs --standard=CakePHP app/Config/database.php >>${RESULTFILE}

phpcs --standard=CakePHP app/Console/Command/PasswordShell.php >>${RESULTFILE}

phpcs --standard=CakePHP app/Model/AppModel.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Attribute.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Bruteforce.php >>${RESULTFILE}
##phpcs --standard=CakePHP app/Model/Correlation.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Dns.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Event.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Role.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Log.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Server.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/User.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Model/Whitelist.php >>${RESULTFILE}

phpcs --standard=CakePHP app/Controller/Component/HidsSha1ExportComponent.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/Component/HidsMd5ExportComponent.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/Component/NidsExportComponent.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/Component/SecureAuthComponent.php >>${RESULTFILE}

phpcs --standard=CakePHP app/Controller/AppController.php >>${RESULTFILE}	# !!!
phpcs --standard=CakePHP app/Controller/AttributesController.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/EventsController.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/ServersController.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/UsersController.php >>${RESULTFILE}
phpcs --standard=CakePHP app/Controller/WhitelistsController.php >>${RESULTFILE}

#mkdir build/code_standards/view
phpcs --standard=CakePHP app/View/Attributes/add_attachment.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/add.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/event.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/search.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Attributes/xml/index.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Elements/actions_menu.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Emails/text/body.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Emails/text/new_event.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Errors/error403.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Helper/AppHelper.php >>${RESULTFILE}	# !!!
phpcs --standard=CakePHP app/View/Layouts/text/default.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Events/add.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/contact.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/edit.ctp >>${RESULTFILE}
#phpcs --standard=CakePHP app/View/Events/event.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/export.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/hids.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/nids.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/text.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/view.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/xml.ctp >>${RESULTFILE}
#CHECK  phpcs --standard=CakePHP app/View/Events/xml/add.ctp >>${RESULTFILE}
#CHECK  phpcs --standard=CakePHP app/View/Events/xml/edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/xml/index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Events/xml/view.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Pages/administration.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Pages/categories_and_types.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Pages/documentation.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Pages/user_management.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Pages/using_the_system.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Servers/add.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Servers/edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Servers/index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Servers/pull.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Servers/push.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Users/admin_add.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/admin_edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/admin_index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/admin_view.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/login.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/memberslist.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/news.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/terms.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Users/view.ctp >>${RESULTFILE}

phpcs --standard=CakePHP app/View/Whitelists/admin_add.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Whitelists/admin_edit.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Whitelists/admin_index.ctp >>${RESULTFILE}
phpcs --standard=CakePHP app/View/Whitelists/admin_view.ctp >>${RESULTFILE}

#phpcs --standard=CakePHP app/Plugin/SysLogLogable/Model/Behavior/SysLogLogableBehavior.php >>${RESULTFILE}
