-- Add capabilities column to agents table and populate from agent_capabilities
ALTER TABLE agents ADD COLUMN IF NOT EXISTS capabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Populate capabilities from agent_capabilities table
UPDATE agents SET capabilities = (
  SELECT jsonb_agg(capability)
  FROM agent_capabilities
  WHERE agent_capabilities.agent_id = agents.id
) WHERE id IN (SELECT DISTINCT agent_id FROM agent_capabilities);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_agents_capabilities ON agents USING GIN(capabilities);
