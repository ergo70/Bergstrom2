CREATE ROLE bergstrom WITH 
	NOSUPERUSER
	NOCREATEDB
	NOCREATEROLE
	NOINHERIT
	LOGIN
	REPLICATION
	NOBYPASSRLS;

create schema ledger;

drop table ledger.ledger;

CREATE TABLE ledger.ledger (
	ordering_clock int8 NOT NULL,
	created double precision not null,
	is_local bool NOT NULL,
	metadata jsonb,
    content bytea not null,
    plaintext_hash bytea not null,
    authentication_tag bytea,
    PKCS1_OAEP_session_key bytea,
    owner_identity_x509 bytea,
    witness_identity_x509 bytea not null,
    witness_signature bytea not null,
    chain_hash bytea not null,
	CONSTRAINT ledger_pkey PRIMARY KEY (ordering_clock)
);

CREATE UNIQUE INDEX ledger_chain_hash_idx ON ledger.ledger (chain_hash);

grant usage on schema ledger to bergstrom;
grant select, insert on ledger.ledger to bergstrom;

-- Table Triggers

CREATE OR REPLACE FUNCTION ledger.tf_ins()
 RETURNS trigger
 LANGUAGE plpgsql
 STRICT
AS $function$  
declare    
begin  
  --if old.ordering_clock > 0 and not exists(SELECT 1 FROM ledger.ledger WHERE (ordering_clock = old.ordering_clock - 1 AND (payload).chain_hash IS NOT NULL AND (payload).witness_signature IS NOT null) or (ordering_clock > old.ordering_clock)) then
  --return null;
 --end if;
  if pg_backend_pid() in ((select pid from pg_stat_activity where backend_type = 'logical replication worker')) then          -- Locally initiated insert or update  
   if not NEW.is_local then                                           -- Judgment, there's a cycle  
      return null;                                                        -- skip  
    else  
      NEW.is_local = false;  
    end if;  
  else                                                                    -- Originated by peer-to-peer nodes insert or update  
    NEW.is_local = true;
  end if;  
  return NEW;  
end;  
$function$
;

create trigger t_ins before
insert
    on
    ledger.ledger for each row execute function ledger.tf_ins();
    
alter table ledger.ledger enable always trigger t_ins;   

CREATE PUBLICATION pub_ledger FOR TABLE ledger.ledger with (publish = 'insert');

CREATE SUBSCRIPTION sub5432_5433 CONNECTION 'host=127.0.0.1 port=5433 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;
CREATE SUBSCRIPTION sub5432_5434 CONNECTION 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger; 
--CREATE SUBSCRIPTION sub5432_5435 CONNECTION 'host=127.0.0.1 port=5435 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger; 

CREATE SUBSCRIPTION sub5433_5432 CONNECTION 'host=127.0.0.1 port=5432 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;  
CREATE SUBSCRIPTION sub5433_5434 CONNECTION 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;
--CREATE SUBSCRIPTION sub5433_5435 CONNECTION 'host=127.0.0.1 port=5435 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger; 

--CREATE SUBSCRIPTION sub5434_5435 CONNECTION 'host=127.0.0.1 port=5435 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;  
CREATE SUBSCRIPTION sub5434_5433 CONNECTION 'host=127.0.0.1 port=5433 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;
CREATE SUBSCRIPTION sub5434_5432 CONNECTION 'host=127.0.0.1 port=5432 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger; 

--CREATE SUBSCRIPTION sub5435_5432 CONNECTION 'host=127.0.0.1 port=5432 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;
--CREATE SUBSCRIPTION sub5435_5433 CONNECTION 'host=127.0.0.1 port=5433 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger;  
--CREATE SUBSCRIPTION sub5435_5434 CONNECTION 'host=127.0.0.1 port=5434 user=bergstrom dbname=postgres sslmode=verify-full sslkey=bergstrom.key sslcert=bergstrom.cert sslrootcert=root.cert' PUBLICATION pub_ledger; 