-- ACL, role table
-- works in conjunction with: CakePHP AclComponent

CREATE TABLE roles (
    id INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    perm_add boolean,
    perm_modify boolean,
    perm_modify_org boolean,
    perm_publish boolean,
    perm_full boolean,
    created DATETIME,
    modified DATETIME
);

-- ALTER TABLE users ADD COLUMN role_id INT(11);

-- data of Roles
-- INSERT INTO roles (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('malware analyst',true,true,false,false);
-- INSERT INTO roles (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('admin',true,true,true,true);
-- INSERT INTO roles (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('IDS analyst',true,true,true,false);
-- INSERT INTO roles (name,perm_add,perm_modify,perm_publish,perm_full) VALUES ('guest',false,false,false,false);

-- CakePHP AclComponent acor & aros tables

-- aros table (should be auto generated on role create)
-- INSERT INTO aros (model,foreign_key,lft,rght) VALUES ('Role',1,1,2);
-- INSERT INTO aros (model,foreign_key,lft,rght) VALUES ('Role',2,3,4);
-- INSERT INTO aros (model,foreign_key,lft,rght) VALUES ('Role',3,5,6);
-- INSERT INTO aros (model,foreign_key,lft,rght) VALUES ('Role',4,7,8);

-- aros_acos
