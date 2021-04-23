--https://github.com/2ndQuadrant/rls-examples/blob/master/signed-vault/signed_vault--1.0.sql
--create extension pgcrypto;
--create schema secret;
set role postgres;
drop table secret.keys;
create table secret.keys (
id bigserial,
    key uuid primary key default gen_random_uuid(),
    key_passphrase uuid default gen_random_uuid(),
    timestamp timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL
);
insert into secret.keys default values;
insert into secret.keys default values;
insert into secret.keys default values;

--drop schema core;
--create schema core;
--grant usage on schema core to api_user;
-- utility function to raise errors
--drop function core.raise(text) cascade;
CREATE OR REPLACE FUNCTION core.raise(error text DEFAULT NULL) RETURNS text AS $$
    BEGIN
--        RAISE '%', coalesce(error, 'PERMISSION_DENIED??');
        RAISE '%', error using hint = 'Not Logged In';
       return 'error';
    END;
    $$ LANGUAGE plpgsql;



   
--     drop FUNCTION set_username(bigint,uuid);
   CREATE or replace FUNCTION set_user(user_info text, passphrase uuid) RETURNS text AS $$
declare
v_timestamp INT;
    v_key   TEXT;
    v_value TEXT;
   v_signature TEXT;
  v_final text;
begin
	
 -- get timestamp and key used for the signature
	v_timestamp := EXTRACT(epoch FROM now());
--    SELECT key INTO v_key FROM secret.keys where id = (select max(id) from secret.keys);
  
    SELECT key INTO v_key FROM secret.keys WHERE key_passphrase = passphrase;
   
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Match Not Found'; --matching key for the supplied passphrase doesn't exist
    END IF;

--    RAISE NOTICE 'The v_key 1 is %',v_key;
   
  -- construct the value and compute the signature (key + username + timestamp)
  -- XXX: may also include other information (e.g. pid)
    v_value := user_info || ':' || v_timestamp;
    v_signature := crypt(v_value || ':' || v_key, gen_salt('bf'));
   
     -- value + signature (without the key)
   v_final := v_value || ':' || v_signature;
--    v_value := v_value || ':' || crypt(v_value || ':' || v_key,
--                                       gen_salt('bf'));
  --do this on the user session?
--    PERFORM set_config('my.id', v_value, false);
    RETURN v_final;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

create or replace function set_user_config(string text) returns boolean as $$
begin
perform set_config('my.id', string, false);
return true;
end;
$$ language plpgsql security definer stable;


--do this on the server, and then open a connection as webuser for the user 
--   CREATE or replace FUNCTION set_user(user_info text, passphrase uuid) RETURNS text AS $$
DO $$ 
DECLARE
UserId BIGINT := 1;
v_key uuid;
   v_result text;
BEGIN 
   select key_passphrase into v_key from secret.keys where id = (select max(id) from secret.keys);
--   RAISE EXCEPTION 'v_key %1' ;
--   RAISE NOTICE 'The v_passphrase is %',v_key;
  select set_user('1', v_key) into v_result;
 perform set_config('my.id', v_result, false);
 raise notice 'the v_result is %', v_result;

END $$;


--select set_username(1, '768aed26-88b0-4b3f-9f22-7fcc2521f9e3');

select current_setting('my.id') as beep; 

--create type user_info as (user_id bigint, site_id bigint, company_id bigint);
--drop function get_user(text);
--CREATE or replace FUNCTION get_user(_type text) RETURNS user_info AS $$
CREATE or replace FUNCTION get_user() RETURNS user_info AS $$
DECLARE
    v_key   TEXT;
    v_parts TEXT[];
    v_user_info TEXT;
    v_value TEXT;
    v_timestamp INT;
    v_signature TEXT;
   	_row text;
  	key_found BOOLEAN := false;
 	res user_info;
 	v_info_parts text[];
 v_id bigint;
BEGIN

	v_parts := regexp_split_to_array(current_setting('my.id', true), ':');
    v_user_info := v_parts[1];
    v_timestamp := v_parts[2];
    v_signature := v_parts[3];
	
   --loop through all keys to see if signature is valid
    for _row in select key from secret.keys loop
--	  raise notice '_row is %', _row;
	     v_value := v_user_info || ':' || v_timestamp || ':' || _row;
	    IF v_signature = crypt(v_value, v_signature) THEN
       key_found = true;
--      raise notice 'key found! % % -- %', key_found, v_user_info, _row;
--	    RETURN v_user_id;
           END IF;
	end loop;

	IF key_found = false THEN
   		RAISE EXCEPTION 'Not Valid...' using HINT = 'No User Found'; --no valid key found
	END IF;

 -- Check that the value is not expired (24 hours (86400))
    IF EXTRACT(epoch FROM now()) > v_timestamp + 86400 THEN
        RAISE EXCEPTION 'signature expired';
    END IF;
   
   v_info_parts := regexp_split_to_array(v_user_info, '-');
--    res.user_id := v_info_parts[1];
    res.user_id := v_info_parts[1];
res.site_id := v_info_parts[2]; 
  res.company_id := v_info_parts[3];
--    res.company_id := v_info_parts[3];
      raise notice 'PART 2 is % - %', res.site_id, v_info_parts[2];
--   RETURN v_user_info as id; --return the user id
  return res;
--  if _type = 'id' then return res.user_id; end if;
 if _type = 'id' then return v_id::bigint; end if;
 if _type = 'site' then return res.site_id; end if;
if _type = 'company' then return res.company_id; end if;

raise exception 'Unknown Type';
--return res;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;


--DROP FUNCTION if exists get_manager();
CREATE or replace FUNCTION get_manager() returns bigint AS $$
DECLARE
    v_key   TEXT;
    v_parts TEXT[];
    v_user_info TEXT;
    v_value TEXT;
    v_timestamp INT;
    v_signature TEXT;
   	_row text;
  	key_found BOOLEAN := false;
 	res user_info;
 	v_info_parts text[];
 v_id bigint;
BEGIN

	v_parts := regexp_split_to_array(current_setting('my.id', true), ':');
    v_user_info := v_parts[1];
    v_timestamp := v_parts[2];
    v_signature := v_parts[3];
	
   --loop through all keys to see if signature is valid
    for _row in select key from secret.keys loop
	     v_value := v_user_info || ':' || v_timestamp || ':' || _row;
	    IF v_signature = crypt(v_value, v_signature) THEN
       key_found = true;
--      raise notice 'key found! % % -- %', key_found, v_user_info, _row;
           END IF;
	end loop;

	IF key_found = false THEN
   		RAISE EXCEPTION 'Not Valid...' using HINT = 'No User Found'; --no valid key found
	END IF;

 -- Check that the value is not expired (24 hours (86400))
    IF EXTRACT(epoch FROM now()) > v_timestamp + 86400 THEN
        RAISE EXCEPTION 'signature expired' using HINT = 'signature expired';
    END IF;
   
--   raise notice 'V_USER_INFO: %', v_user_info;
   return v_user_info as id; --return the verified user id
   
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
-- everyone can run the function (that's why we have the signature)
GRANT ALL ON FUNCTION get_manager() TO PUBLIC;

--DROP FUNCTION if exists get_employee();
CREATE or replace FUNCTION get_employee() RETURNS bigint AS $$
DECLARE
    v_key   TEXT;
    v_parts TEXT[];
    v_user_info TEXT;
    v_value TEXT;
    v_timestamp INT;
    v_signature TEXT;
   	_row text;
  	key_found BOOLEAN := false;
 	res user_info;
 	v_info_parts text[];
 v_id bigint;
BEGIN

	v_parts := regexp_split_to_array(current_setting('my.id', true), ':');
    v_user_info := v_parts[1];
    v_timestamp := v_parts[2];
    v_signature := v_parts[3];
	
   --loop through all keys to see if signature is valid
    for _row in select key from secret.keys loop
	     v_value := v_user_info || ':' || v_timestamp || ':' || _row;
	    IF v_signature = crypt(v_value, v_signature) THEN
       key_found = true;
--      raise notice 'key found! % % -- %', key_found, v_user_info, _row;
           END IF;
	end loop;

	IF key_found = false THEN
   		RAISE EXCEPTION 'Not Valid...' using HINT = 'No User Found'; --no valid key found
	END IF;

 -- Check that the value is not expired (24 hours (86400))
    IF EXTRACT(epoch FROM now()) > v_timestamp + 86400 THEN
        RAISE EXCEPTION 'signature expired' using HINT = 'signature expired';
    END IF;
   
   return v_user_info as id; --return the verified user id
   
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

GRANT ALL ON FUNCTION get_employee() TO PUBLIC;

--select current_setting('my.id') as beep; 

-- select set_config('my.id', '4:1619022174:$2a$06$f3pwFg1mUiTv29xsv1x8iuQViz3QPE/5UzHsy5afwTVAaiGL14TkS', false);

--select (get_user()).user_id;
select get_employee();
select get_manager();


   drop table if exists managers cascade;
  create table managers (
    id          bigserial primary key,
    username    text not null unique,
    salary int
       );
   
      drop table if exists employees cascade;
create table employees (
    id          bigserial primary key,
    username    text not null unique,
    salary  int,
    manager bigint references managers(id)
    );
   
drop table if exists users cascade;
create table users (
    id          bigserial primary key,
    username    text not null unique,
    company bigint,
    site bigint, 
    role int,
    salary  int,
    manager bigint references managers(id)
    );

   drop table if exists products cascade;
  create table products (
    id          bigserial primary key,
    name    text unique,
    price smallint,
    quantity int
    );


INSERT INTO users (username, site, company, role) VALUES ('tom', 1, 1, 1), ('bob', 2,2,0);
INSERT INTO managers (username, salary) VALUES ('manager1', 35000), ('manager2', 37000);

insert into products (name, price, quantity) values ('ipad', 999, 20);
insert into products (name, price, quantity) values ('iphone', 699, 15);

INSERT INTO employees (username, salary, manager) VALUES ('employee1', 24000, 1), ('employee2', 23000, 2);

--create role api_user with login password 'superpass';
--create schema api;
GRANT USAGE ON SCHEMA api to api_user;
--create view api.users as
--	with _user_id as (select get_user('id') )
--	select
--	id,
--case when _user_id is not null then username
--	else 'nope' end as username,
--	case when _user_id as bigint = id then company
--	else 'not allow' end as company
--	from users, _user_id;

--create or replace view api.users as
--with user_id as (select (get_user()).user_id)
--select id,
--site,
--role,
--case when user_id is not null then username
--else 'nope' end as username,
--case when id = user_id then company
--else null end as company
--from public.users, user_id;
--
--CREATE RULE _UPDATE AS ON UPDATE TO api.users DO INSTEAD
--UPDATE public.users SET
--    username = CASE WHEN OLD.id = (get_user()).user_id THEN NEW.username
--        else core.raise()::text END
--    WHERE id = OLD.id;
    

--managers can see their own employees, and update and item price and quantity
create or replace view api.managers as
with manager_id as (select get_manager())  -- can't get this to work, it returns a record instead of bigint
select 
-- logged in managers can see all ids and usernames, but only their own salary
case when  get_manager() is not null then id::text
else core.raise() end as id,
case when  get_manager() is not null then username
else core.raise() end as username,
--case when get_manager() = id then salary
case when  get_manager() = id then salary
else null end as salary
from public.managers, manager_id;

CREATE RULE _UPDATE AS ON UPDATE TO api.managers DO INSTEAD
UPDATE public.managers SET
    username = CASE WHEN OLD.id::bigint = get_manager() THEN NEW.username
        else core.raise()::text end
--        else old.username END
    WHERE id = OLD.id::bigint;
   
 
   
 --managers can see their own employees, and update and item price and quantity
create or replace view api.employees as
--with manager_id as (select get_manager()),
--employee_id as (select get_employee())
select
case when get_manager() is not null then id
else null end as id,
case when get_manager() is not null then username
else null end as username,
case when get_manager() is not null then manager
else null end as manager,
case when get_manager() = manager then salary
else null end as salary
--case when manager = get_manager() then (id, username, salary, manager)::text
--else core.raise() end as package
--case when get_employee() = id then (id, username, salary, manager)::text 
--else core.raise() end as em_package
from public.employees;


create or replace view api.products as
select *
from public.products;

       ALTER TABLE products ENABLE ROW LEVEL SECURITY;
--drop policy if exists users_access_policy on public.users;
create policy manager_access_policy on public.products to api_user 
    USING (get_manager() is not null);
   
   create policy employee_access_policy on public.products to api_user 
    USING (get_employee() is not null); 
   


 create or replace view api.users as 
 select 
 id,
username,
company,
 case 
 when (id = (get_user()).user_id) then role 
 else null end as role,
 case
 when (id = (get_user()).user_id) then site 
 else null end as site
-- case when ((select role from users where id = (get_user()).user_id) >= 1) then company
-- else '0' end as company
from public.users;

CREATE RULE _UPDATE AS ON UPDATE TO api.users DO INSTEAD
UPDATE public.users SET
    site = CASE WHEN OLD.id = (get_user()).user_id THEN NEW.site
        else old.site end,
    username = CASE WHEN OLD.id = (get_user()).user_id THEN NEW.username
    	else old.username end
    WHERE id = OLD.id;

ALTER VIEW api.users owner to api_user;

 grant select,
     insert,
     update (username, site), --only allowed to update username
     delete on users to api_user;
    
    ---manager table rights ---
    ALTER VIEW api.managers owner to api_user;
 grant select,
     insert,
     update (username), --only allowed to update username
     delete on managers to api_user;
    
    --employee table rights --   
    ALTER VIEW api.employees owner to api_user;
 grant select,
     insert,
     update (username, salary), --only allowed to update username
     delete on employees to api_user;
    
    --product table rights
    
        ALTER VIEW api.products owner to api_user;
 grant select,
     insert,
     update (quantity), 
     delete on products to api_user;
    
    
    create view api.employees_v2 as
    select *, get_manager() as manager_id from employees;

   ALTER VIEW api.employees_v2 owner to api_user;

      alter table employees enable row level security;
     
  create policy manager_access_policy on public.employees for select to api_user 
    USING (manager = get_manager());
   
     create policy manager_update_policy on public.employees for update to api_user 
    USING (manager = get_manager());
   
   
   
     
       ALTER TABLE users ENABLE ROW LEVEL SECURITY;
--drop policy if exists users_access_policy on public.users;
--create policy users_access_policy on public.users to api_user 
--    USING (role <= (select role from users where id = (get_user()).user_id)); -- you can only see your own user profile;
--   using (username = 'bob');
--        WITH CHECK (id = (get_user()).user_id);
      
create policy update_username_access_policy on public.users for update to api_user 
    USING (id = (get_user()).user_id);
   
   create policy allow_select_access_policy on public.users for select to api_user 
    USING (true);
        
grant usage on users_id_seq to api_user;

    

set role api_user;

select * from api.employees_v2;
update api.employees_v2 set salary = 20000;
select * from api.employees_v2;
select * from api.employees;

-- select (get_user()).user_id;
--select * from api.users;

--update api.users set username = 'Bob was here' where id = 1;
--update api.users set username = 'Bob was here';
--update api.users set site = 5;

--select * from api.users;

select * from api.managers;
select * from api.employees;

select * from api.products;

--sign out and try to access products table
--select set_user_config('');
--select * from api.products;

set role postgres;
		
		
