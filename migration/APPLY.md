# Apply the migration pack

`pack.json` in this folder is a read-only export of the user's laptop OpenBot
server: 11 agent profiles, 5 sidebar sections, 7 routines with schedules,
8 agent `AGENTS.md` bodies, and 2 local skills.

The user wants this cloud server to mirror that team. Recreate the items with
your own OpenBot tools; do not edit `pack.json`.

## Order of work

1. **Agents** — for each entry in `agents`, in the given order, create an agent
   with the same `name`, `title`, `description`, `notifications`, `access`,
   `computerUse`, `avatarSeed` and `avatarHue`. Use a model that is available
   on this server; when the listed `model` is missing, keep the agent on the
   server default. Skip a name that already exists.
2. **Instructions** — write each agent's `agentsMd` into that agent's
   workspace `AGENTS.md`. Leave `agentsMd` untouched when it is `null`.
3. **Sections** — create the sidebar sections in `sections` order and put each
   listed agent in its section.
4. **Routines** — create every routine for the agent named in `agentName`,
   using `instruction`, `timezone`, `limitPolicy`, `missedPolicy`, `runIn` and
   `schedule`. Create a routine `active` only when `cloudReady` is `true`;
   otherwise create it paused, because it needs the user's laptop (local
   Windows paths, WhatsApp desktop, or a local disk audit).
5. **Skills** — install each skill from `skills[].skillMd`, keeping the
   frontmatter name.
6. **User instructions** — `userInstructions` holds the user-level rule files.
   Apply them only if this server exposes a place for user-level instructions;
   never overwrite files outside the user's own instruction slots.

## Hard rules

- Never copy provider credentials, tokens, or local Windows paths from the pack.
- Never create a duplicate when an item with the same name exists; update it
  instead.
- Keep the routines paused when `cloudReady` is `false`, and say which ones in
  the final report.
- Finish with a short table: agents created, sections, routines active/paused,
  skills installed, and anything skipped with the reason.
