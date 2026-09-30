/*
# Add editable training content and signup bootstrap

1. New Columns
- `subscribers.training_protocol`: coach-authored protocol text shown in a details window.
- `subscribers.coach_notice`: coach-authored notice shown to the member.
- `subscribers.youtube_url`: optional exercise-video URL entered manually by the coach.
- `progress_logs.exercise_name`: optional exercise name for each saved workout entry.
- `progress_logs.weight_used`: optional working weight saved with the workout record.
- `progress_logs.rest_seconds`: optional rest duration used for the session.

2. Security
- Existing row-level policies continue to protect member-owned records and admin management.
- A signup trigger creates the member profile and subscriber record automatically, so account creation does not depend on a second browser write.

3. Important Notes
- Training content starts empty by design and can be filled manually by the administrator.
- No existing user data is deleted or changed.
*/

ALTER TABLE public.subscribers ADD COLUMN IF NOT EXISTS training_protocol text NOT NULL DEFAULT '';
ALTER TABLE public.subscribers ADD COLUMN IF NOT EXISTS coach_notice text NOT NULL DEFAULT '';
ALTER TABLE public.subscribers ADD COLUMN IF NOT EXISTS youtube_url text NOT NULL DEFAULT '';
ALTER TABLE public.progress_logs ADD COLUMN IF NOT EXISTS exercise_name text NOT NULL DEFAULT '';
ALTER TABLE public.progress_logs ADD COLUMN IF NOT EXISTS weight_used numeric(6,2) NOT NULL DEFAULT 0 CHECK (weight_used >= 0 AND weight_used <= 1000);
ALTER TABLE public.progress_logs ADD COLUMN IF NOT EXISTS rest_seconds integer NOT NULL DEFAULT 90 CHECK (rest_seconds >= 0 AND rest_seconds <= 3600);

CREATE OR REPLACE FUNCTION public.bootstrap_new_member()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, role)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data ->> 'full_name', ''), 'member')
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.subscribers (user_id, full_name)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data ->> 'full_name', ''))
  ON CONFLICT (user_id) DO NOTHING;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created_oao ON auth.users;
CREATE TRIGGER on_auth_user_created_oao
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.bootstrap_new_member();

REVOKE EXECUTE ON FUNCTION public.bootstrap_new_member() FROM PUBLIC, anon, authenticated;
