-- Audit, log table
-- works in conjunction with:
-- https://github.com/alkemann/CakePHP-Assets/wiki
-- also described at:
-- http://bakery.cakephp.org/articles/alkemann/2008/10/21/logablebehavior

DROP TABLE logs;
CREATE TABLE logs (
  id int(11) NOT NULL AUTO_INCREMENT,
  title varchar(255),
  created DATETIME,
  description varchar(255),
  model varchar(20),
  model_id int(11),
  action varchar(20),
  user_id  int(11),
  `change` varchar(255),
  email  varchar(255),
  org varchar(255) COLLATE utf8_bin,
  PRIMARY KEY (id)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=2 ;