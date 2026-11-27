-- Settings → Email → Reminder: also remind people who haven't answered the questions (same day as the availability reminder).
-- instances.q_reminded = that reminder went out for this round (reset when the reply-by date changes).
ALTER TABLE polls ADD COLUMN remind_questions INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN q_reminded INTEGER NOT NULL DEFAULT 0;
