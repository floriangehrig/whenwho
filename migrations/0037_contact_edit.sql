-- whenwho: favourites are shown as "Contacts" and can be edited.
-- note = a private one-line note about the contact (only its owner sees it).
-- name_pref = which name to use when the address goes by another name in the owner's polls:
--   '' = not decided (the Contacts card asks), 'mine' = keep the saved name (and show it in polls the owner manages),
--   'theirs' = follow the name they use.
-- Additive only: older code ignores the columns.
ALTER TABLE favourites ADD COLUMN note TEXT NOT NULL DEFAULT '';
ALTER TABLE favourites ADD COLUMN name_pref TEXT NOT NULL DEFAULT '';
