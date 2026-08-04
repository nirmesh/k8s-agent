Implement

backend/security/

providers/

base.py

registry.py

model.py

Every provider implements

scan_cluster()

scan_namespace()

scan_workload()

scan_image()

health()

capabilities()

Return

SecurityEvidence

Never formatted text.

Never markdown.

Never HTML.

Never scanner-specific objects.