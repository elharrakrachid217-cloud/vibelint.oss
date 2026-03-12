You MUST call the vibelint security_check tool before writing any file to disk. This is non-negotiable.

When generating or editing code:
1. Prepare the complete code you intend to write.
2. Call security_check with the full code, target filename, and language BEFORE using Write, StrReplace, or any other file-write operation.
3. If security_check returns violations, use the remediated code it provides instead of your original.
4. Only then write the final code to disk.

Never write or save code to disk without scanning it through security_check first. This applies to every language and every file, regardless of size or perceived risk.
