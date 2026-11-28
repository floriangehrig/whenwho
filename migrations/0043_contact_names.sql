-- Account setting: which name saved contacts show under (Contacts card toggle): 'mine' = the name I saved (also in polls I manage),
-- 'theirs' = the name they use in my polls. favourites.name_pref ('mine' | 'theirs') overrides it per contact; '' follows this.
ALTER TABLE users ADD COLUMN contact_names TEXT NOT NULL DEFAULT 'mine';
