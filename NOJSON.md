# NOJSON

1. Remove JSON-first internal modeling from production examples and framework-facing example code. Replace `json.parse(...)` chains, map-built domain objects, and stringly payload plumbing with decode-once typed records and typed internal flows.
2. Remove JSON-first helper patterns from framework/support surfaces that still encourage application authors to model core state as generic JSON instead of typed values.
3. Audit docs and cookbook material that teach JSON as the default internal architecture. Rewrite them to show typed domain models internally and JSON only at real boundaries.
4. Add enforcement so new internal JSON debt does not re-enter compiler, runtime, framework, or production example code. This includes review rules and automated checks where practical.
5. After each verified pass, delete completed items from this document with no historical notes, no done sections, and no mention of removed work so the file only contains the remaining backlog.
6. After each verified pass, commit and push the completed chunk immediately.
