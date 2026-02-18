# How to Test Remote Shell & Remote Control

## Prerequisites
✅ Agent is enrolled: `agent_id: 1bc83a24-10c1-4c64-a316-7a6958fdebb1`
✅ Heartbeats are arriving
✅ Metrics are collected

## To Execute Remote Shell

### Via UI (Dashboard)
1. **Go to**: Agents → Select your agent → "Remote Shell" tab
2. **Type command** (e.g., `ipconfig` on Windows)
3. **Click "Execute"**
4. Backend creates a **Job** in DB with status='pending'
5. Next **heartbeat** from agent → backend sends the job
6. Agent receives **JobAssign** message, executes command
7. Agent sends **JobResult** back with stdout/stderr

### Via API (curl/Postman)
```bash
curl -X POST http://localhost:4000/api/jobs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "1bc83a24-10c1-4c64-a316-7a6958fdebb1",
    "job_type": "run_script",
    "payload": {
      "interpreter": "powershell",
      "script": "Get-ScheduledTask -TaskName MASSVISION-Reap3r-Agent | Select-Object State"
    }
  }'
```

## Debug Checklist

### 1. Check if Job was Created
```bash
ssh root@72.62.181.194 "psql postgresql://reap3r:reap3r_secret@localhost:5432/reap3r -c \
  \"SELECT id, agent_id, type, status, created_at FROM jobs WHERE agent_id = '1bc83a24-10c1-4c64-a316-7a6958fdebb1' ORDER BY created_at DESC LIMIT 5;\""
```

### 2. Check Backend Logs for Job Dispatch
```bash
ssh root@72.62.181.194 "pm2 logs reap3r-backend --lines 200 --nostream 2>&1 | grep -E 'JobAssign|dispatch|1bc83a24'"
```

### 3. Check Agent Logs on Windows
```powershell
Get-Content 'C:\ProgramData\Reap3r\logs\agent.log' -Tail 100 | Select-String -Pattern 'JobAssign','job_id','execute','ERROR'
```

## Expected Log Output

**Backend** (when sending job):
```
Dispatched job [job-id] to agent [agent-id]
```

**Agent** (when receiving and executing):
```
[2026-02-18 13:35:22] [INFO] Received JobAssign: job_id=abc123, type=run_script
[2026-02-18 13:35:23] [INFO] Executing: powershell -Command "..."
[2026-02-18 13:35:24] [INFO] Job result: exit_code=0, stdout="..."
```

## Common Issues

| Issue | Diagnosis | Fix |
|-------|-----------|-----|
| No jobs appear in UI | Job not created in DB | Use API call to create job manually |
| Job created but agent doesn't get it | Agent heartbeat not sent | Check agent logs, restart Scheduled Task |
| Agent receives job but doesn't execute | Agent crashed or permissions issue | Check `agent.log` for ERROR or WARN |
| Job shows "pending" forever | Agent didn't send JobResult back | Check agent WS connectivity |

