# VIBELINT_ENFORCEMENT_START
VibeLint fail-closed enforcement rules:

1) Before any file write (create/modify/patch), call MCP tool `security_check`
   with the COMPLETE final file contents.
2) If `security_check` returns violations, write ONLY the returned remediated code.
3) If MCP server `vibelint` is unavailable or `security_check` cannot run,
   DO NOT write files. Stop and ask the user to re-enable VibeLint.
4) This rule applies to every language and every file, even small edits.
# VIBELINT_ENFORCEMENT_END
