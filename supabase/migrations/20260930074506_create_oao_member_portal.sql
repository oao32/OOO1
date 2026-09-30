/*
# Create OAO member portal data model

1. New Tables
- `profiles`: one private account profile per signed-in user, including display name and protected role.
- `subscribers`: training profile and subscription details for a member, managed by the coach and visible to its owner.
- `progress_logs`: dated measurements and daily habits belonging to a subscriber.

2. Security
- Row-level security is enabled on every new table.
- Members can read their own profile, subscriber record, and progress logs.
- Administrators can manage all subscriber and progress data.
- The role column is protected from browser updates; only a privileged, admin-checked function can change it.

3. Important Notes
- The browser never supplies ownership values; they default from the signed-in session.
- Account creation uses Supabase email/password authentication and the frontend creates the matching profile row.
- Promote the coach account to `admin` through a trusted database operation after creating it, if the first account is not already configured by the project owner.
*/

CREATE TABLE IF NOT EXISTS public.profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name text NOT NULL DEFAULT '',
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.subscribers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE DEFAULT auth.uid(),
  full_name text NOT NULL,
  phone text NOT NULL DEFAULT '',
  weight numeric(5,2) NOT NULL DEFAULT 0 CHECK (weight >= 0 AND weight <= 500),
  height numeric(5,2) NOT NULL DEFAULT 0 CHECK (height >= 0 AND height <= 300),
  muscle_mass numeric(5,2) NOT NULL DEFAULT 0 CHECK (muscle_mass >= 0 AND muscle_mass <= 300),
  body_fat numeric(5,2) NOT NULL DEFAULT 0 CHECK (body_fat >= 0 AND body_fat <= 100),
  subscription_start date NOT NULL DEFAULT current_date,
  duration_days integer NOT NULL DEFAULT 30 CHECK (duration_days > 0 AND duration_days <= 3650),
  plan_name text NOT NULL DEFAULT 'برنامج إعادة التكوين',
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.progress_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subscriber_id uuid NOT NULL REFERENCES public.subscribers(id) ON DELETE CASCADE,
  logged_on date NOT NULL DEFAULT current_date,
  weight numeric(5,2) NOT NULL DEFAULT 0 CHECK (weight >= 0 AND weight <= 500),
  water_liters numeric(4,2) NOT NULL DEFAULT 0 CHECK (water_liters >= 0 AND water_liters <= 20),
  completed_exercises integer NOT NULL DEFAULT 0 CHECK (completed_exercises >= 0 AND completed_exercises <= 100),
  notes text NOT NULL DEFAULT '',
  created_by uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS subscribers_subscription_start_idx ON public.subscribers (subscription_start);
CREATE INDEX IF NOT EXISTS progress_logs_subscriber_date_idx ON public.progress_logs (subscriber_id, logged_on DESC);

CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.profiles
    WHERE id = auth.uid() AND role = 'admin'
  );
$$;

CREATE OR REPLACE FUNCTION public.set_member_role(p_member uuid, p_role text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT public.is_admin() THEN
    RAISE EXCEPTION 'Not authorized';
  END IF;
  IF p_role NOT IN ('member', 'admin') THEN
    RAISE EXCEPTION 'Invalid role';
  END IF;
  UPDATE public.profiles SET role = p_role, updated_at = now() WHERE id = p_member;
END;
$$;

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.progress_logs ENABLE ROW LEVEL SECURITY;

REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (full_name) ON public.profiles TO authenticated;
REVOKE INSERT (role) ON public.profiles FROM authenticated;

DROP POLICY IF EXISTS "profiles_select_own_or_admin" ON public.profiles;
CREATE POLICY "profiles_select_own_or_admin" ON public.profiles FOR SELECT TO authenticated
USING (auth.uid() = id OR public.is_admin());
DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;
CREATE POLICY "profiles_insert_own" ON public.profiles FOR INSERT TO authenticated
WITH CHECK (auth.uid() = id AND role = 'member');
DROP POLICY IF EXISTS "profiles_update_own_name" ON public.profiles;
CREATE POLICY "profiles_update_own_name" ON public.profiles FOR UPDATE TO authenticated
USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
DROP POLICY IF EXISTS "profiles_delete_own" ON public.profiles;
CREATE POLICY "profiles_delete_own" ON public.profiles FOR DELETE TO authenticated
USING (auth.uid() = id);

DROP POLICY IF EXISTS "subscribers_select_own_or_admin" ON public.subscribers;
CREATE POLICY "subscribers_select_own_or_admin" ON public.subscribers FOR SELECT TO authenticated
USING (auth.uid() = user_id OR public.is_admin());
DROP POLICY IF EXISTS "subscribers_insert_own_or_admin" ON public.subscribers;
CREATE POLICY "subscribers_insert_own_or_admin" ON public.subscribers FOR INSERT TO authenticated
WITH CHECK (auth.uid() = user_id OR public.is_admin());
DROP POLICY IF EXISTS "subscribers_update_own_or_admin" ON public.subscribers;
CREATE POLICY "subscribers_update_own_or_admin" ON public.subscribers FOR UPDATE TO authenticated
USING (auth.uid() = user_id OR public.is_admin())
WITH CHECK (auth.uid() = user_id OR public.is_admin());
DROP POLICY IF EXISTS "subscribers_delete_admin" ON public.subscribers;
CREATE POLICY "subscribers_delete_admin" ON public.subscribers FOR DELETE TO authenticated
USING (public.is_admin());

DROP POLICY IF EXISTS "progress_select_own_or_admin" ON public.progress_logs;
CREATE POLICY "progress_select_own_or_admin" ON public.progress_logs FOR SELECT TO authenticated
USING (EXISTS (SELECT 1 FROM public.subscribers s WHERE s.id = subscriber_id AND (s.user_id = auth.uid() OR public.is_admin())));
DROP POLICY IF EXISTS "progress_insert_own_or_admin" ON public.progress_logs;
CREATE POLICY "progress_insert_own_or_admin" ON public.progress_logs FOR INSERT TO authenticated
WITH CHECK ((created_by = auth.uid()) AND EXISTS (SELECT 1 FROM public.subscribers s WHERE s.id = subscriber_id AND (s.user_id = auth.uid() OR public.is_admin())));
DROP POLICY IF EXISTS "progress_update_own_or_admin" ON public.progress_logs;
CREATE POLICY "progress_update_own_or_admin" ON public.progress_logs FOR UPDATE TO authenticated
USING (created_by = auth.uid() OR public.is_admin())
WITH CHECK (created_by = auth.uid() OR public.is_admin());
DROP POLICY IF EXISTS "progress_delete_own_or_admin" ON public.progress_logs;
CREATE POLICY "progress_delete_own_or_admin" ON public.progress_logs FOR DELETE TO authenticated
USING (created_by = auth.uid() OR public.is_admin());

REVOKE EXECUTE ON FUNCTION public.set_member_role(uuid, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_member_role(uuid, text) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.is_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated;
