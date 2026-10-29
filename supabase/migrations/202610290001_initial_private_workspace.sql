-- CRTracking initial private-by-default workspace schema
-- Apply in a new Supabase project's SQL Editor. Review before running.
-- This migration creates the baseline data model; it does not configure Auth email delivery,
-- production hosting, scheduled reminders, or invitations.

begin;

create extension if not exists pgcrypto;

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 1 and 100),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'admin' check (role in ('admin', 'standard', 'restricted')),
  joined_at timestamptz not null default now(),
  primary key (workspace_id, user_id)
);

create table if not exists public.spaces (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null check (char_length(trim(name)) between 1 and 100),
  category text not null default 'personal' check (category in ('personal', 'family', 'work', 'custom')),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, workspace_id)
);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  space_id uuid,
  title text not null check (char_length(trim(title)) between 1 and 240),
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'done', 'cancelled')),
  priority text not null default 'normal' check (priority in ('low', 'normal', 'high', 'urgent')),
  due_at timestamptz,
  completed_at timestamptz,
  created_by uuid not null references auth.users(id),
  assigned_to uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (space_id, workspace_id) references public.spaces(id, workspace_id) on delete cascade
);

create table if not exists public.calendar_events (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  space_id uuid,
  title text not null check (char_length(trim(title)) between 1 and 240),
  description text,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  location text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (ends_at > starts_at),
  foreign key (space_id, workspace_id) references public.spaces(id, workspace_id) on delete cascade
);

create table if not exists public.time_entries (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  space_id uuid,
  task_id uuid references public.tasks(id) on delete set null,
  job_name text not null check (char_length(trim(job_name)) between 1 and 120),
  started_at timestamptz,
  ended_at timestamptz,
  duration_minutes integer not null check (duration_minutes between 1 and 10080),
  note text check (note is null or char_length(note) <= 1000),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  check (ended_at is null or started_at is null or ended_at >= started_at),
  foreign key (space_id, workspace_id) references public.spaces(id, workspace_id) on delete cascade
);

create table if not exists public.user_preferences (
  user_id uuid primary key references auth.users(id) on delete cascade,
  timezone text not null default 'America/New_York',
  quiet_hours_enabled boolean not null default false,
  quiet_hours_start time,
  quiet_hours_end time,
  default_reminder_minutes integer not null default 15 check (default_reminder_minutes between 0 and 10080),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (quiet_hours_enabled = false) or
    (quiet_hours_start is not null and quiet_hours_end is not null)
  )
);

create index if not exists workspace_members_user_idx on public.workspace_members(user_id);
create index if not exists spaces_workspace_idx on public.spaces(workspace_id);
create index if not exists tasks_workspace_due_idx on public.tasks(workspace_id, due_at);
create index if not exists tasks_assigned_to_idx on public.tasks(assigned_to);
create index if not exists calendar_events_workspace_start_idx on public.calendar_events(workspace_id, starts_at);
create index if not exists time_entries_workspace_created_idx on public.time_entries(workspace_id, created_by, created_at desc);

-- Security-definer helpers prevent recursive RLS evaluation on workspace_members.
create or replace function public.is_workspace_member(target_workspace uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id = target_workspace and wm.user_id = (select auth.uid())
  );
$$;

create or replace function public.can_manage_workspace(target_workspace uuid)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id = target_workspace
      and wm.user_id = (select auth.uid())
      and wm.role = 'admin'
  );
$$;

revoke all on function public.is_workspace_member(uuid) from public, anon;
revoke all on function public.can_manage_workspace(uuid) from public, anon;
grant execute on function public.is_workspace_member(uuid) to authenticated;
grant execute on function public.can_manage_workspace(uuid) to authenticated;

-- Automatically make the creator the initial admin; no client can self-assign membership.
create or replace function public.add_workspace_creator_as_admin()
returns trigger
language plpgsql security definer
set search_path = ''
as $$
begin
  insert into public.workspace_members (workspace_id, user_id, role)
  values (new.id, new.created_by, 'admin');
  return new;
end;
$$;

drop trigger if exists trg_workspace_creator_admin on public.workspaces;
create trigger trg_workspace_creator_admin
after insert on public.workspaces
for each row execute function public.add_workspace_creator_as_admin();

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.spaces enable row level security;
alter table public.tasks enable row level security;
alter table public.calendar_events enable row level security;
alter table public.time_entries enable row level security;
alter table public.user_preferences enable row level security;

drop policy if exists workspaces_select_member on public.workspaces;
create policy workspaces_select_member on public.workspaces
for select to authenticated using (public.is_workspace_member(id));
drop policy if exists workspaces_insert_creator on public.workspaces;
create policy workspaces_insert_creator on public.workspaces
for insert to authenticated with check (created_by = (select auth.uid()));
drop policy if exists workspaces_update_admin on public.workspaces;
create policy workspaces_update_admin on public.workspaces
for update to authenticated using (public.can_manage_workspace(id))
with check (public.can_manage_workspace(id));
drop policy if exists workspaces_delete_admin on public.workspaces;
create policy workspaces_delete_admin on public.workspaces
for delete to authenticated using (public.can_manage_workspace(id));

drop policy if exists members_select_same_workspace on public.workspace_members;
create policy members_select_same_workspace on public.workspace_members
for select to authenticated using (public.is_workspace_member(workspace_id));
-- Membership changes are intentionally not granted to browser clients; invitation/admin flow comes later.

drop policy if exists spaces_member_access on public.spaces;
create policy spaces_member_access on public.spaces
for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));

drop policy if exists tasks_member_access on public.tasks;
create policy tasks_member_access on public.tasks
for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
  and (assigned_to is null or exists (
    select 1 from public.workspace_members wm
    where wm.workspace_id = tasks.workspace_id and wm.user_id = tasks.assigned_to
  ))
);

drop policy if exists calendar_events_member_access on public.calendar_events;
create policy calendar_events_member_access on public.calendar_events
for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (public.is_workspace_member(workspace_id) and created_by = (select auth.uid()));

drop policy if exists time_entries_member_access on public.time_entries;
create policy time_entries_member_access on public.time_entries
for all to authenticated
using (public.is_workspace_member(workspace_id))
with check (
  public.is_workspace_member(workspace_id)
  and created_by = (select auth.uid())
  and (task_id is null or exists (
    select 1 from public.tasks t
    where t.id = time_entries.task_id and t.workspace_id = time_entries.workspace_id
  ))
);

drop policy if exists user_preferences_self_access on public.user_preferences;
create policy user_preferences_self_access on public.user_preferences
for all to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

-- Grant only the browser roles/operations required by the initial app.
-- RLS still determines which rows each authenticated user may access.
revoke all on public.workspaces, public.workspace_members, public.spaces,
  public.tasks, public.calendar_events, public.time_entries, public.user_preferences
from anon, authenticated;

grant select, insert, update, delete on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, insert, update, delete on public.spaces, public.tasks,
  public.calendar_events, public.time_entries, public.user_preferences to authenticated;

commit;
