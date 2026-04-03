-- GA-1: Seed data — initial users and agents
-- Design: docs/design-auth-aaa.md v2

INSERT OR IGNORE INTO users (id, email, display_name, role) VALUES
  ('andreas', 'andreas@meta-factory.ai', 'Andreas', 'admin'),
  ('jc', 'jc@meta-factory.ai', 'JC', 'operator');

INSERT OR IGNORE INTO agents (id, display_name, owner_id, class, backend) VALUES
  ('luna', 'Luna', 'andreas', 'pet', 'local');
