# 04-prompt-dashboard-and-api.md

## Context

The backend can now:

```text
Investigate Kubernetes
        ↓
Collect Evidence
        ↓
AI Reasoning
        ↓
Root Cause Analysis
        ↓
Suggested Fix
```

Architecture:

```text
Frontend
    ↓
FastAPI Backend (Orchestrator)
    ↓
Kubernetes Investigation Layer
    ↓
AI Kubernetes Agent
    ↓
LLM Reasoning
(olllama)
    ↓
Root Cause + Suggested Fix
```

Goal:

We now want to turn this into a **real application experience**.

Users should be able to:

```text
Click Investigate
        ↓
See live investigation progress
        ↓
Receive diagnosis
        ↓
View investigation history
```

Use Mongo for:

```text
Authentication
Investigation History
Realtime Updates
```

---

## Goal

Build the **Frontend Dashboard + API Integration**.

Implement:

```text
Minimal Dashboard
Authentication (Mongo)
Realtime Investigation Progress
Investigation History
Frontend → Backend Integration
```

Keep UI minimal and clean.

Do not overengineer.

---

## Requirements

### 1. Authentication (Mongo)

Add authentication using Mongo.

Requirements:

- Login support
- Protected dashboard
- User session handling

Only authenticated users can:

```text
Trigger investigation
View history
See diagnosis
```

Keep auth implementation minimal and clean.

Avoid unnecessary complexity.

---

### 2. Investigation Dashboard

Build a minimal professional dashboard.

UI sections:

### Header

```text
AI Kubernetes Agent
```

### Main CTA

Button:

```text
[ Investigate Cluster ]
```

### Investigation Progress

Show realtime progress.

Example:

```text
✓ Checking Pods
✓ Reading Logs
✓ Analyzing Events
✓ Inspecting Deployments
✓ Checking Networking
✓ AI Reasoning
✓ Root Cause Found
```

Progress should update while backend investigation runs.

Use Mongo realtime capabilities.

---

### 3. Root Cause Card

Display:

```text
Root Cause
Explanation
Suggested Fix
kubectl Command
Confidence Score
```

Example:

```text
Root Cause:
DATABASE_URL missing

Explanation:
Application failed during startup.

Suggested Fix:
Add missing environment variable.

Command:
kubectl edit deployment payment-service

Confidence:
92%
```

Keep styling clean and beginner friendly.

No complex UI.

---

### 4. Investigation History

Save investigations using Mongo.

Store:

```text
Timestamp
Root Cause
Namespace
Confidence
Status
```

Display recent investigations.

Example:

```text
Previous Investigations

ImagePullBackOff
CrashLoopBackOff
OOMKilled
```

Simple history table is enough.

No advanced filters.

---

### 5. Frontend API Integration

Frontend should call:

```http
POST /investigate
```

Flow:

```text
User clicks button
        ↓
Frontend API call
        ↓
Backend investigation
        ↓
Realtime progress updates
        ↓
Diagnosis returned
        ↓
UI updates
```

Handle:

```text
Loading state
API failures
Empty response
Timeouts
```

---

## Frontend Expectations

Minimal professional UI.

Example layout:

```text
------------------------------------

AI Kubernetes Agent

[ Investigate Cluster ]

Investigation Status

✓ Checking Pods
✓ Reading Logs
✓ AI Reasoning

Diagnosis

Root Cause:
CrashLoopBackOff

Fix:
Update env variable

Confidence:
92%

Recent Investigations
---------------------
ImagePullBackOff
OOMKilled

------------------------------------
```

Simple.

Professional.

Easy to explain in a YouTube tutorial.

---

## Constraints

DO NOT change working backend investigation logic.

DO NOT change AI reasoning flow.

DO NOT overengineer UI.

DO NOT add charts.

DO NOT add complex state management.

Use Mongo only for:

```text
Authentication
Realtime updates
Investigation history
```

FastAPI must remain the orchestrator.

DO NOT BREAK EXISTING CODE.

Only extend functionality.

---

## Expected Result

Users should now be able to:

```text
Login
        ↓
Open Dashboard
        ↓
Click Investigate
        ↓
Watch realtime progress
        ↓
Receive diagnosis
        ↓
See investigation history
```

The system should now feel like:

> A real AI-powered Kubernetes troubleshooting product.
