CREATE VIRTUAL TABLE IF NOT EXISTS skills_fts USING fts5(
  name,
  description,
  domain,
  subdomain,
  tags,
  attack,
  nist,
  path
);
