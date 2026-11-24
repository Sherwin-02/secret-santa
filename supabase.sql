-- Secret Santa database setup for Supabase.
-- Paste this whole file into Supabase → SQL Editor → New query → Run.
-- Safe to run again: it only creates what's missing and replaces the functions.
--
-- Security model: the tables are locked (row level security on, no policies), so the
-- public API key cannot read or write them directly. The web page can only call the
-- ss_* functions below, and each one checks a PIN, a session token or the admin password.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- ---------- Tables ----------
create table if not exists public.ss_settings (
  id int primary key default 1 check (id = 1),
  event_name text not null default 'Secret Santa',
  budget text not null default '',
  exchange_date text not null default '',
  note text not null default '',
  admin_hash text,
  admin_failed int not null default 0,
  admin_locked_until timestamptz,
  drawn_at timestamptz
);
insert into public.ss_settings (id) values (1) on conflict do nothing;

create table if not exists public.ss_families (
  id uuid primary key default gen_random_uuid(),
  name text not null default '',
  sort int not null default 0
);

create table if not exists public.ss_people (
  id uuid primary key default gen_random_uuid(),
  family_id uuid not null references public.ss_families(id) on delete cascade,
  name text not null,
  sort int not null default 0,
  email text,
  phone text,
  pin_hash text,
  registered_at timestamptz,
  viewed_at timestamptz,
  failed int not null default 0,
  locked_until timestamptz,
  session_token text unique,
  receiver_id uuid references public.ss_people(id) on delete set null
);
create unique index if not exists ss_people_name_uq on public.ss_people (lower(btrim(name)));

create table if not exists public.ss_messages (
  id bigserial primary key,
  santa_id uuid not null references public.ss_people(id) on delete cascade,
  giftee_id uuid not null references public.ss_people(id) on delete cascade,
  from_santa boolean not null,
  body text not null check (length(body) between 1 and 1000),
  created_at timestamptz not null default now()
);

alter table public.ss_settings enable row level security;
alter table public.ss_families enable row level security;
alter table public.ss_people   enable row level security;
alter table public.ss_messages enable row level security;
revoke all on public.ss_settings, public.ss_families, public.ss_people, public.ss_messages from anon, authenticated;
revoke all on sequence public.ss_messages_id_seq from anon, authenticated;

-- ---------- Helpers (not callable from the web) ----------
create or replace function public._ss_event() returns jsonb
language sql stable security definer set search_path = public, extensions, pg_temp as $$
  select jsonb_build_object('name', event_name, 'budget', budget, 'date', exchange_date,
                            'note', note, 'drawn', drawn_at is not null, 'setup', admin_hash is not null)
  from ss_settings where id = 1
$$;

-- Returns null when the password is right, otherwise an error code. Never raises,
-- so the failed-attempt counter is saved.
create or replace function public._ss_admin(p_pw text) returns text
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare s ss_settings;
begin
  select * into s from ss_settings where id = 1 for update;
  if s.admin_hash is null then return 'no_admin'; end if;
  if s.admin_locked_until is not null and s.admin_locked_until > now() then return 'locked'; end if;
  if p_pw is not null and crypt(p_pw, s.admin_hash) = s.admin_hash then
    update ss_settings set admin_failed = 0, admin_locked_until = null where id = 1;
    return null;
  end if;
  update ss_settings
     set admin_failed = case when admin_failed + 1 >= 8 then 0 else admin_failed + 1 end,
         admin_locked_until = case when admin_failed + 1 >= 8 then now() + interval '10 minutes' else null end
   where id = 1;
  return 'wrong_password';
end $$;

create or replace function public._ss_err(p_code text, p_extra jsonb default '{}'::jsonb) returns jsonb
language sql immutable set search_path = public, pg_temp as $$ select jsonb_build_object('ok', false, 'error', p_code) || p_extra $$;

-- ---------- Public functions for players ----------
create or replace function public.ss_public() returns jsonb
language sql stable security definer set search_path = public, extensions, pg_temp as $$
  select jsonb_build_object('ok', true, 'event', _ss_event(),
           'names', coalesce((select jsonb_agg(name order by lower(name)) from ss_people), '[]'::jsonb))
$$;

create or replace function public.ss_register(p_name text, p_email text, p_phone text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare p ss_people; tok text;
begin
  if coalesce(p_pin, '') !~ '^[0-9]{4}$' then return _ss_err('bad_pin'); end if;
  if coalesce(btrim(p_email), '') !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then return _ss_err('bad_email'); end if;
  if length(regexp_replace(coalesce(p_phone, ''), '[^0-9]', '', 'g')) < 8 then return _ss_err('bad_phone'); end if;
  select * into p from ss_people where lower(btrim(name)) = lower(btrim(p_name)) for update;
  if not found then return _ss_err('not_found'); end if;
  if p.pin_hash is not null then return _ss_err('taken'); end if;
  tok := encode(gen_random_bytes(24), 'hex');
  update ss_people
     set email = btrim(p_email), phone = btrim(p_phone), pin_hash = crypt(p_pin, gen_salt('bf', 8)),
         registered_at = now(), session_token = tok, failed = 0, locked_until = null
   where id = p.id;
  return jsonb_build_object('ok', true, 'token', tok);
end $$;

create or replace function public.ss_login(p_name text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare p ss_people; tok text; f int;
begin
  select * into p from ss_people where lower(btrim(name)) = lower(btrim(p_name)) for update;
  if not found then return _ss_err('not_found'); end if;
  if p.pin_hash is null then return _ss_err('not_registered'); end if;
  if p.locked_until is not null and p.locked_until > now() then
    return _ss_err('locked', jsonb_build_object('minutes', ceil(extract(epoch from p.locked_until - now()) / 60)));
  end if;
  if crypt(coalesce(p_pin, ''), p.pin_hash) = p.pin_hash then
    tok := coalesce(p.session_token, encode(gen_random_bytes(24), 'hex'));
    update ss_people set failed = 0, locked_until = null, session_token = tok where id = p.id;
    return jsonb_build_object('ok', true, 'token', tok);
  end if;
  f := p.failed + 1;
  if f >= 5 then
    update ss_people set failed = 0, locked_until = now() + interval '15 minutes' where id = p.id;
    return _ss_err('locked', jsonb_build_object('minutes', 15));
  end if;
  update ss_people set failed = f where id = p.id;
  return _ss_err('wrong_pin', jsonb_build_object('left', 5 - f));
end $$;

create or replace function public.ss_me(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare p ss_people; g ss_people; santa uuid;
begin
  if coalesce(p_token, '') = '' then return _ss_err('session'); end if;
  select * into p from ss_people where session_token = p_token;
  if not found then return _ss_err('session'); end if;
  if p.receiver_id is not null then
    select * into g from ss_people where id = p.receiver_id;
    if p.viewed_at is null then update ss_people set viewed_at = now() where id = p.id; end if;
  end if;
  select id into santa from ss_people where receiver_id = p.id;
  return jsonb_build_object('ok', true, 'event', _ss_event(), 'name', p.name,
    'email', p.email, 'phone', p.phone,
    'giftee', g.name,
    'to_giftee', coalesce((select jsonb_agg(jsonb_build_object('mine', m.from_santa, 'body', m.body, 'at', m.created_at) order by m.id)
                           from ss_messages m where m.santa_id = p.id and m.giftee_id = p.receiver_id), '[]'::jsonb),
    'from_santa', coalesce((select jsonb_agg(jsonb_build_object('mine', not m.from_santa, 'body', m.body, 'at', m.created_at) order by m.id)
                           from ss_messages m where m.giftee_id = p.id and m.santa_id = santa), '[]'::jsonb),
    'has_santa', santa is not null);
end $$;

create or replace function public.ss_send(p_token text, p_to text, p_body text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare p ss_people; santa uuid; recent int; b text := btrim(coalesce(p_body, ''));
begin
  select * into p from ss_people where coalesce(p_token, '') <> '' and session_token = p_token;
  if not found then return _ss_err('session'); end if;
  if length(b) = 0 or length(b) > 1000 then return _ss_err('bad_message'); end if;
  select count(*) into recent from ss_messages
   where created_at > now() - interval '10 minutes'
     and ((santa_id = p.id and from_santa) or (giftee_id = p.id and not from_santa));
  if recent >= 30 then return _ss_err('slow_down'); end if;
  if p_to = 'giftee' then
    if p.receiver_id is null then return _ss_err('not_drawn'); end if;
    insert into ss_messages (santa_id, giftee_id, from_santa, body) values (p.id, p.receiver_id, true, b);
  elsif p_to = 'santa' then
    select id into santa from ss_people where receiver_id = p.id;
    if santa is null then return _ss_err('not_drawn'); end if;
    insert into ss_messages (santa_id, giftee_id, from_santa, body) values (santa, p.id, false, b);
  else
    return _ss_err('bad_target');
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Admin functions ----------
create or replace function public.ss_admin_setup(p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
begin
  if length(coalesce(p_pw, '')) < 6 then return _ss_err('short_password'); end if;
  update ss_settings set admin_hash = crypt(p_pw, gen_salt('bf', 8)) where id = 1 and admin_hash is null;
  if not found then return _ss_err('already_setup'); end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ss_admin_state(p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  return jsonb_build_object('ok', true, 'event', _ss_event(),
    'families', coalesce((
      select jsonb_agg(jsonb_build_object('id', f.id, 'name', f.name, 'people', coalesce((
          select jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name, 'email', p.email, 'phone', p.phone,
                   'registered', p.pin_hash is not null, 'viewed', p.viewed_at is not null,
                   'locked', p.locked_until is not null and p.locked_until > now()) order by p.sort, p.name)
          from ss_people p where p.family_id = f.id), '[]'::jsonb)) order by f.sort, f.name)
      from ss_families f), '[]'::jsonb));
end $$;

create or replace function public.ss_admin_save_event(p_pw text, p_event jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  update ss_settings set
    event_name = left(coalesce(nullif(btrim(p_event->>'name'), ''), 'Secret Santa'), 120),
    budget = left(coalesce(p_event->>'budget', ''), 60),
    exchange_date = left(coalesce(p_event->>'date', ''), 120),
    note = left(coalesce(p_event->>'note', ''), 1000)
  where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- p_families: [{id, name, people: [{id, name}]}]. Replaces the whole list.
create or replace function public.ss_admin_save_people(p_pw text, p_families jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw); f jsonb; p jsonb; fi int := 0; pi int; dup text;
begin
  if e is not null then return _ss_err(e); end if;
  if (select drawn_at from ss_settings where id = 1) is not null then return _ss_err('already_drawn'); end if;
  select lower(btrim(x->>'name')) into dup
    from jsonb_array_elements(p_families) fam, jsonb_array_elements(fam->'people') x
   group by 1 having count(*) > 1 limit 1;
  if dup is not null then return _ss_err('duplicate_name', jsonb_build_object('name', dup)); end if;

  delete from ss_people where id not in (
    select (x->>'id')::uuid from jsonb_array_elements(p_families) fam, jsonb_array_elements(fam->'people') x);
  delete from ss_families where id not in (select (fam->>'id')::uuid from jsonb_array_elements(p_families) fam);
  -- park names so swaps/renames don't trip the unique index mid-update
  update ss_people set name = '~' || id::text where true;

  for f in select * from jsonb_array_elements(p_families) loop
    fi := fi + 1;
    insert into ss_families (id, name, sort) values ((f->>'id')::uuid, left(coalesce(f->>'name', ''), 80), fi)
      on conflict (id) do update set name = excluded.name, sort = excluded.sort;
    pi := 0;
    for p in select * from jsonb_array_elements(f->'people') loop
      pi := pi + 1;
      if btrim(coalesce(p->>'name', '')) = '' then return _ss_err('empty_name'); end if;
      insert into ss_people (id, family_id, name, sort)
      values ((p->>'id')::uuid, (f->>'id')::uuid, left(btrim(p->>'name'), 60), pi)
      on conflict (id) do update set family_id = excluded.family_id, name = excluded.name, sort = excluded.sort;
    end loop;
  end loop;
  return jsonb_build_object('ok', true);
end $$;

-- Checks the draw using totals only (never returns who got whom).
create or replace function public._ss_draw_check() returns jsonb
language sql stable security definer set search_path = public, extensions, pg_temp as $$
  with c as (select
    (select count(*) from ss_people) as people,
    (select count(*) from ss_people where receiver_id is not null) as giving,
    (select count(distinct receiver_id) from ss_people) as receiving,
    (select count(*) from ss_people where receiver_id = id) as self,
    (select count(*) from ss_people p join ss_people r on r.id = p.receiver_id where r.family_id = p.family_id) as same_family)
  select jsonb_build_object('people', people, 'giving', giving, 'receiving', receiving, 'self', self, 'same_family', same_family,
    'valid', people >= 3 and giving = people and receiving = people and self = 0 and same_family = 0) from c
$$;

create or replace function public.ss_admin_check(p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  return jsonb_build_object('ok', true, 'check', _ss_draw_check());
end $$;

-- Database rules: nobody can be drawn twice, nobody can draw themselves.
create unique index if not exists ss_people_receiver_uq on public.ss_people (receiver_id) where receiver_id is not null;
do $$ begin
  alter table public.ss_people add constraint ss_people_not_self check (receiver_id is distinct from id);
exception when duplicate_object then null; end $$;

-- The draw runs here in the database, so nobody's browser (not even the admin's) ever sees the pairs.
create or replace function public.ss_admin_draw(p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  e text := _ss_admin(p_pw);
  ids uuid[]; fams uuid[]; n int; biggest int;
  ord int[]; taken boolean[]; assign int[]; cands int[]; gi int; pick int; ok boolean := false;
begin
  if e is not null then return _ss_err(e); end if;
  if (select drawn_at from ss_settings where id = 1) is not null then return _ss_err('already_drawn'); end if;
  select array_agg(id order by id), array_agg(family_id order by id) into ids, fams from ss_people;
  n := coalesce(array_length(ids, 1), 0);
  if n < 3 then return _ss_err('too_few'); end if;
  select max(c) into biggest from (select count(*) c from ss_people group by family_id) t;
  if biggest * 2 > n then return _ss_err('family_too_big', jsonb_build_object('size', biggest, 'total', n)); end if;

  for attempt in 1..3000 loop
    -- biggest families pick first, random order within the same size
    select array_agg(i order by cnt desc, random()) into ord
      from (select i, count(*) over (partition by fams[i]) cnt from generate_series(1, n) i) t;
    taken := array_fill(false, array[n]);
    assign := array_fill(0, array[n]);
    ok := true;
    foreach gi in array ord loop
      select array_agg(j) into cands from generate_series(1, n) j
       where not taken[j] and fams[j] <> fams[gi];
      if cands is null then ok := false; exit; end if;
      pick := cands[1 + floor(random() * array_length(cands, 1))::int];
      taken[pick] := true;
      assign[gi] := pick;
    end loop;
    exit when ok;
  end loop;
  if not ok then return _ss_err('no_solution'); end if;

  delete from ss_messages where true;
  update ss_people p set receiver_id = ids[assign[t.i]], viewed_at = null
    from generate_series(1, n) t(i) where p.id = ids[t.i];
  -- Belt and braces: if anything about the result is wrong, undo everything.
  if not (_ss_draw_check()->>'valid')::boolean then raise exception 'Draw verification failed'; end if;
  update ss_settings set drawn_at = now() where id = 1;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ss_admin_undo_draw(p_pw text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  delete from ss_messages where true;
  update ss_people set receiver_id = null, viewed_at = null where true;
  update ss_settings set drawn_at = null where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- Clears someone's sign-up (forgotten PIN, or someone else claimed their name). Their match stays.
create or replace function public.ss_admin_reset_person(p_pw text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  update ss_people set email = null, phone = null, pin_hash = null, registered_at = null,
         session_token = null, failed = 0, locked_until = null where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ss_admin_password(p_pw text, p_new text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare e text := _ss_admin(p_pw);
begin
  if e is not null then return _ss_err(e); end if;
  if length(coalesce(p_new, '')) < 6 then return _ss_err('short_password'); end if;
  update ss_settings set admin_hash = crypt(p_new, gen_salt('bf', 8)) where id = 1;
  return jsonb_build_object('ok', true);
end $$;

-- ---------- Who may call what ----------
revoke execute on function public._ss_event(), public._ss_admin(text), public._ss_err(text, jsonb), public._ss_draw_check() from public, anon, authenticated;
revoke execute on function
  public.ss_public(), public.ss_register(text, text, text, text), public.ss_login(text, text),
  public.ss_me(text), public.ss_send(text, text, text),
  public.ss_admin_setup(text), public.ss_admin_state(text), public.ss_admin_save_event(text, jsonb),
  public.ss_admin_save_people(text, jsonb), public.ss_admin_draw(text), public.ss_admin_undo_draw(text),
  public.ss_admin_reset_person(text, uuid), public.ss_admin_password(text, text), public.ss_admin_check(text)
from public;
grant execute on function
  public.ss_public(), public.ss_register(text, text, text, text), public.ss_login(text, text),
  public.ss_me(text), public.ss_send(text, text, text),
  public.ss_admin_setup(text), public.ss_admin_state(text), public.ss_admin_save_event(text, jsonb),
  public.ss_admin_save_people(text, jsonb), public.ss_admin_draw(text), public.ss_admin_undo_draw(text),
  public.ss_admin_reset_person(text, uuid), public.ss_admin_password(text, text), public.ss_admin_check(text)
to anon, authenticated;
