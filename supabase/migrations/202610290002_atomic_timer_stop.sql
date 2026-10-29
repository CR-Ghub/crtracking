-- Atomic timer stop: save the time entry and remove the active timer in one transaction.
-- Apply this migration in the Supabase SQL Editor before using the updated timer-stop UI.

create or replace function public.stop_active_timer(target_timer_id uuid)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_timer public.active_timers%rowtype;
  v_entry_id uuid;
  v_ended_at timestamptz := clock_timestamp();
  v_duration_minutes integer;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required';
  end if;

  select t.*
    into v_timer
    from public.active_timers t
   where t.id = target_timer_id
     and t.user_id = (select auth.uid())
   for update;

  if not found then
    raise exception 'Active timer not found or not owned by the signed-in user';
  end if;

  if not exists (
    select 1 from public.workspace_members wm
     where wm.workspace_id = v_timer.workspace_id
       and wm.user_id = (select auth.uid())
  ) then
    raise exception 'Workspace membership required';
  end if;

  if v_timer.job_id is not null and not exists (
    select 1 from public.jobs j
     where j.id = v_timer.job_id
       and j.workspace_id = v_timer.workspace_id
  ) then
    raise exception 'Timer job does not belong to its workspace';
  end if;

  if v_timer.task_id is not null and not exists (
    select 1 from public.tasks t
     where t.id = v_timer.task_id
       and t.workspace_id = v_timer.workspace_id
  ) then
    raise exception 'Timer task does not belong to its workspace';
  end if;

  v_duration_minutes := greatest(1, ceil(extract(epoch from (v_ended_at - v_timer.started_at)) / 60)::integer);

  if v_duration_minutes > 10080 then
    raise exception 'Timer exceeds the maximum supported entry duration of 7 days. Contact support before stopping it.';
  end if;

  insert into public.time_entries (
    workspace_id, job_id, task_id, started_at, ended_at,
    duration_minutes, note, created_by
  ) values (
    v_timer.workspace_id, v_timer.job_id, v_timer.task_id,
    v_timer.started_at, v_ended_at, v_duration_minutes,
    v_timer.note, (select auth.uid())
  )
  returning id into v_entry_id;

  delete from public.active_timers
   where id = v_timer.id
     and user_id = (select auth.uid());

  if not found then
    raise exception 'Timer changed before it could be stopped';
  end if;

  return v_entry_id;
end;
$$;

revoke all on function public.stop_active_timer(uuid) from public, anon;
grant execute on function public.stop_active_timer(uuid) to authenticated;
