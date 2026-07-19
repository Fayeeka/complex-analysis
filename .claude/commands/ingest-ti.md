---
name: ingest-ti
description: Ingest a threat intelligence report URL and extract TTPs, IOCs, and a simulation plan
arguments:
  - name: url
    description: URL to the threat intel report
    required: true
---

# Threat Intelligence Ingestion

## Step 1: Extract Content

Run defuddle to get clean content from the URL:
```bash
defuddle parse "$url" --markdown
```

## Step 2: Analyze the Content

With the extracted content, identify:

### Threat Overview
- Campaign/threat actor name (if mentioned)
- Target industries/regions
- Time period of activity

### TTPs (Tactics, Techniques, Procedures)
Map observed behaviors to MITRE ATT&CK across all relevant tactic categories. For each technique:
- ATT&CK ID (e.g., T1566.001)
- How it was used in this campaign
- Confidence level (high/medium/low based on detail in report)

### Indicators of Compromise
Extract any IOCs mentioned: IP addresses, domains, file hashes, file paths, registry keys, email addresses

### Simulation Plan
Based on the TTPs identified, suggest Atomic Red Team tests:
- List applicable atomic tests by technique ID
- Note any techniques that don't have atomic tests
- Prioritize by: techniques with high confidence + available atomic tests

## Step 3: Output

Create a structured markdown file in analysis/ with:
- Filename: analysis/ti-[date]-[campaign-name].md
- Frontmatter with source URL and extraction date
- All sections above
- Links to ATT&CK technique pages
