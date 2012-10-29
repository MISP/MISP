alter table servers add column lastpulledid int;
alter table servers add column lastpushedid int;
alter table servers add column organization varchar(10);
-- alter table servers add column logo varchar(20);

-- example data
-- INSERT INTO servers (url,organization,logo) VALUES ('http://192.101.252.40/','NATO NCI','natologo.gif');