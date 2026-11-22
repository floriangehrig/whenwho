-- whenwho: questions per round (extra info for the round or its meetings, and votes on options such as places).
-- instances.questions = JSON list of the organiser's questions (see validateQuestions in the Worker).
-- responses.extra = JSON { a: { questionId: answer }, add: { questionId: [{ id, label }] } }: a person's answers and the
-- options they suggested (kept in their own answer so they go when the answer or account goes). NULL = nothing.
-- Additive only: older code ignores the columns.
ALTER TABLE instances ADD COLUMN questions TEXT;
ALTER TABLE responses ADD COLUMN extra TEXT;
