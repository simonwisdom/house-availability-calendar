-- Add morning availability tracking alongside evening

ALTER TABLE daily_availability
  ADD COLUMN is_free_morning INTEGER NOT NULL DEFAULT 0;

ALTER TABLE daily_summary
  ADD COLUMN free_count_morning INTEGER NOT NULL DEFAULT 0;

ALTER TABLE daily_summary
  ADD COLUMN free_user_ids_morning TEXT;

ALTER TABLE daily_summary
  ADD COLUMN free_count_evening INTEGER NOT NULL DEFAULT 0;

ALTER TABLE daily_summary
  ADD COLUMN free_user_ids_evening TEXT;

-- Backfill new evening columns from legacy aggregate data
UPDATE daily_summary
   SET free_count_evening = free_count,
       free_user_ids_evening = free_user_ids;
