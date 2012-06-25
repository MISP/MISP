-- ACL, group table
-- works in conjunction with: CakePHP AclComponent

CREATE TABLE groups (
    id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    perm_add boolean,
    perm_modify boolean,
    perm_publish boolean,
    perm_full boolean,
    created DATETIME,
    modified DATETIME
);

ALTER TABLE users ADD COLUMN group_id INT(11);

-- data of Groups
INSERT INTO groups (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('malware analyst',true,true,false,false);
INSERT INTO groups (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('admin',true,true,true,true);
INSERT INTO groups (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('IDS analyst',true,true,true,false);
INSERT INTO groups (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('guest',false,false,false,false);

-- CakePHP AclComponents acor & aros tables

-- insert into aros (model,foreign_key,lft,rght) values ('Group',1,1,2);
-- insert into aros (model,foreign_key,lft,rght) values ('Group',2,3,4);
-- insert into aros (model,foreign_key,lft,rght) values ('Group',3,5,6);
-- insert into aros (model,foreign_key,lft,rght) values ('Group',4,7,8);