-- whenwho: answers to a round's questions, stored per person per round apart from the availability answer
-- (people can fill in the questions without answering the dates). extra = { a: { questionId: answer }, add: { questionId: [{ id, label }] } }.
-- edit_hash = secret edit key of a guest (like responses.edit_hash). Existing answers (responses.extra, 0022) are copied over;
-- responses.extra is no longer used.
CREATE TABLE form_answers (
  id TEXT PRIMARY KEY,
  poll_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  participant_id TEXT NOT NULL,
  extra TEXT,
  edit_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (instance_id, participant_id)
);
CREATE INDEX form_answers_poll ON form_answers (poll_id);
CREATE INDEX form_answers_part ON form_answers (participant_id);
INSERT OR IGNORE INTO form_answers (id, poll_id, instance_id, participant_id, extra, edit_hash, created_at, updated_at)
  SELECT id, poll_id, instance_id, participant_id, extra, edit_hash, created_at, updated_at
  FROM responses WHERE extra IS NOT NULL AND participant_id IS NOT NULL;
