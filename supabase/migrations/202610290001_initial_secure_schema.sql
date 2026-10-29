-- CRTracking initial secure schema
-- Apply in Supabase SQL Editor. This migration is intentionally additive and does not modify the existing live site.
begin;

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Member',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  created_by uuid not null references auth.users(id) on delete restrict,
  created_at timestamptz not null default now()
);

create table if not exists public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'standard' check (role in ('owner','admin','standard','restricted')),
  created_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);
create index if not exists workspace_members_user_idx on public.workspace_members(user_id);

create table if not exists public.spaces (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 100),
  kind text not null default 'personal' check (kind in ('personal','family','work','custom')),
  is_private boolean not null default true,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
create index if not exists spaces_workspace_idx on public.spaces(workspace_id);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  space_id uuid references public.spaces(id) on delete set null,
  title text not null check (char_length(title) between 1 and 240),
  description text,
  status text not null default 'todo' check (status in ('todo','in_progress','blocked','done','cancelled')),
  priority text not null default 'normal' check (priority in ('low','normal','high','urgent')),
  due_at timestamptz,
  starts_at timestamptz,
  recurrence_rule text,
  assigned_to uuid references auth.users(id) on delete set null,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (description is null or char_length(description) <= 10000)
);
create index if not exists tasks_workspace_due_idx on public.tasks(workspace_id, due_at);
create index if not exists tasks_assigned_idx on public.tasks(assigned_to);

create table if not exists public.calendar_events (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  space_id uuid references public.spaces(id) on delete set null,
  title text not null check (char_length(title) between 1 and 240),
  details text,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  location text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (ends_at > starts_at)
);
create index if not exists calendar_events_workspace_start_idx on public.calendar_events(workspace_id, starts_at);

create table if not exists public.jobs (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 120),
  weekly_target_hours numeric(5,2) not null default 0 check (weekly_target_hours between 0 and 168),
  deadline_day smallint check (deadline_day between 0 and 6),
  timezone text not null default 'America/New_York',
  is_active boolean not null default true,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists jobs_workspace_idx on public.jobs(workspace_id);

create table if not exists public.time_entries (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  job_id uuid references public.jobs(id) on delete set null,
  task_id uuid references public.tasks(id) on delete set null,
  started_at timestamptz,
  ended_at timestamptz,
  duration_minutes integer not null check (duration_minutes between 1 and 10080),
  note text check (note is null or char_length(note) <= 2000),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((started_at is null and ended_at is null) or (started_at is not null and ended_at is not null and ended_at > started_at))
);
create index if not exists time_entries_workspace_created_idx on public.time_entries(workspace_id, created_at desc);
create index if not exists time_entries_job_idx on public.time_entries(job_id);

create table if not exists public.active_timers (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  job_id uuid references public.jobs(id) on delete set null,
  task_id uuid references public.tasks(id) on delete set null,
  user_id uuid not null references auth.users(id) on delete cascade,
  started_at timestamptz not null default now(),
  reminder_after_minutes integer not null default 120 check (reminder_after_minutes between 15 and 1440),
  last_reminded_at timestamptz,
  note text,
  created_at timestamptz not null default now(),
  unique (user_id)
);
create index if not exists active_timers_workspace_idx on public.active_timers(workspace_id);

create table if not exists public.reminder_preferences (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email_enabled boolean not null default true,
  quiet_hours_enabled boolean not null default false,
  quiet_start time,
  quiet_end time,
  timezone text not null default 'America/New_York',
  snooze_minutes integer not null default 15 check (snooze_minutes between 1 and 1440),
  updated_at timestamptz not null default now(),
  check ((quiet_start is null and quiet_end is null) or (quiet_start is not null and quiet_end is not null))
);

-- SECURITY DEFINER membership helpers avoid recursive workspace_members RLS checks.
create or replace function public.is_workspace_member(target_workspace uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id = target_workspace
      and wm.user_id = (select auth.uid())
  );
$$;

create or replace function public.is_workspace_creator(target_workspace uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspaces w
    where w.id = target_workspace
      and w.created_by = (select auth.uid())
  );
$$;

create or replace function public.has_workspace_role(target_workspace uuid, allowed_roles text[])
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id = target_workspace
      and wm.user_id = (select auth.uid())
      and wm.role = any(allowed_roles)
  );
$$;

revoke all on function public.is_workspace_member(uuid) from public, anon;
revoke all on function public.has_workspace_role(uuid, text[]) from public, anon;
revoke all on function public.is_workspace_creator(uuid) from public, anon;
grant execute on function public.is_workspace_member(uuid) to authenticated;
grant execute on function public.has_workspace_role(uuid, text[]) to authenticated;
grant execute on function public.is_workspace_creator(uuid) to authenticated;

-- Enable RLS on every exposed table.
alter table public.profiles enable row level security;
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.spaces enable row level security;
alter table public.tasks enable row level security;
alter table public.calendar_events enable row level security;
alter table public.jobs enable row level security;
alter table public.time_entries enable row level security;
alter table public.active_timers enable row level security;
alter table public.reminder_preferences enable row level security;

-- Explicit least-privilege grants; no signed-out API access.
revoke all on public.profiles, public.workspaces, public.workspace_members, public.spaces,
  public.tasks, public.calendar_events, public.jobs, public.time_entries,
  public.active_timers, public.reminder_preferences from anon, authenticated;
grant select, insert, update on public.profiles to authenticated;
grant select, insert, update on public.workspaces to authenticated;
grant select, insert, update, delete on public.workspace_members to authenticated;
grant select, insert, update, delete on public.spaces, public.tasks, public.calendar_events,
  public.jobs, public.time_entries to authenticated;
grant select, insert, update, delete on public.active_timers to authenticated;
grant select, insert, update on public.reminder_preferences to authenticated;

-- Profile: only the signed-in user can access their profile.
drop policy if exists profiles_select_self on public.profiles;
create policy profiles_select_self on public.profiles for select to authenticated using (id = (select auth.uid()));
drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self on public.profiles for insert to authenticated with check (id = (select auth.uid()));
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Workspace creation is owner-only initially; invite/admin workflows will be added deliberately later.
drop policy if exists workspaces_select_member on public.workspaces;
create policy workspaces_select_member on public.workspaces for select to authenticated
using (public.is_workspace_member(id) or created_by = (select auth.uid()));
drop policy if exists workspaces_insert_creator on public.workspaces;
create policy workspaces_insert_creator on public.workspaces for insert to authenticated with check (created_by = (select auth.uid()));
drop policy if exists workspaces_update_owner_admin on public.workspaces;
create policy workspaces_update_owner_admin on public.workspaces for update to authenticated using (public.has_workspace_role(id, array['owner','admin'])) with check (public.has_workspace_role(id, array['owner','admin']));

-- Membership: members can see their workspace membership list; a workspace creator can add only themselves as owner.
drop policy if exists workspace_members_select_member on public.workspace_members;
create policy workspace_members_select_member on public.workspace_members for select to authenticated using (public.is_workspace_member(workspace_id));
drop policy if exists workspace_members_insert_creator_self on public.workspace_members;
create policy workspace_members_insert_creator_self on public.workspace_members for insert to authenticated
with check (
  user_id = (select auth.uid())
  and role = 'owner'
  and public.is_workspace_creator(workspace_id)
);
drop policy if exists workspace_members_update_admin on public.workspace_members;
create policy workspace_members_update_admin on public.workspace_members for update to authenticated
using (public.has_workspace_role(workspace_id, array['owner','admin']))
with check (public.has_workspace_role(workspace_id, array['owner','admin']));
drop policy if exists workspace_members_delete_admin on public.workspace_members;
create policy workspace_members_delete_admin on public.workspace_members for delete to authenticated
using (public.has_workspace_role(workspace_id, array['owner','admin']) and user_id <> (select auth.uid()));

-- All workspace data requires membership. Private spaces are visible only to their creator unless marked shared.
drop policy if exists spaces_select_member on public.spaces;
create policy spaces_select_member on public.spaces for select to authenticated
using (public.is_workspace_member(workspace_id) and (not is_private or created_by = (select auth.uid())));
drop policy if exists spaces_insert_member on public.spaces;
create policy spaces_insert_member on public.spaces for insert to authenticated
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));
drop policy if exists spaces_update_member on public.spaces;
create policy spaces_update_member on public.spaces for update to authenticated
using (public.is_workspace_member(workspace_id) and (not is_private or created_by = (select auth.uid())))
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));
drop policy if exists spaces_delete_member on public.spaces;
create policy spaces_delete_member on public.spaces for delete to authenticated
using (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));

-- Workspace data policies; membership is required for all operations.
drop policy if exists tasks_member_all on public.tasks;
create policy tasks_member_all on public.tasks for all to authenticated
using (
  public.is_workspace_member(workspace_id)
  and (
    space_id is null
    or exists (
      select 1 from public.spaces s
      where s.id = space_id
        and s.workspace_id = tasks.workspace_id
        and (not s.is_private or s.created_by = (select auth.uid()))
    )
  )
)
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
  and (
    space_id is null
    or exists (
      select 1 from public.spaces s
      where s.id = space_id
        and s.workspace_id = tasks.workspace_id
        and (not s.is_private or s.created_by = (select auth.uid()))
    )
  )
);
drop policy if exists calendar_events_member_all on public.calendar_events;
create policy calendar_events_member_all on public.calendar_events for all to authenticated
using (
  public.is_workspace_member(workspace_id)
  and (
    space_id is null
    or exists (
      select 1 from public.spaces s
      where s.id = space_id
        and s.workspace_id = calendar_events.workspace_id
        and (not s.is_private or s.created_by = (select auth.uid()))
    )
  )
)
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
  and (
    space_id is null
    or exists (
      select 1 from public.spaces s
      where s.id = space_id
        and s.workspace_id = calendar_events.workspace_id
        and (not s.is_private or s.created_by = (select auth.uid()))
    )
  )
);
drop policy if exists jobs_member_all on public.jobs;
create policy jobs_member_all on public.jobs for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));
drop policy if exists time_entries_member_all on public.time_entries;
create policy time_entries_member_all on public.time_entries for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));
drop policy if exists active_timers_owner_all on public.active_timers;
create policy active_timers_owner_all on public.active_timers for all to authenticated
using (user_id = (select auth.uid()) and public.is_workspace_member(workspace_id))
with check (user_id = (select auth.uid()) and public.is_workspace_member(workspace_id));
drop policy if exists reminder_preferences_self_all on public.reminder_preferences;
create policy reminder_preferences_self_all on public.reminder_preferences for all to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

commit();
