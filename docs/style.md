# Documentation style

The register, the emphasis rules, and the punctuation conventions every document under `docs/` is
written to, together with the terminology it uses. A reference manual describes a system; it does
not argue for one.

Most of what follows is subtractive. Where a rule and a habit disagree, the rule wins and the habit
is the defect.

## Scope

Everything by CLAUDE.md is in scope, including javadoc and the site.

## Register

Documentation is written in the third person, in the present tense, about the system.

- The subject of a sentence is the thing being described, not the reader and not the author. Write
  "a `PUT` raises a proposal", not "you will get a proposal back".
- Second person is correct in two places. The first is the numbered steps of a procedure, where the
  imperative is the clearest form: "Upload the bundle." "Roll the service." Everything around those
  steps returns to the third person.
- Do not address the reader's expectations, assumptions, or feelings. "That is the platform working,
  not failing" and "worth knowing without opening it" describe a conversation rather than a system.
- Do not write in the first person, singular or plural. The documentation has no narrator.

## Emphasis

Bold marks the first occurrence of a defined term in the document that defines it. It has no other
use. Bold applied to a clause for stress has a cumulative effect: where a fifth of the text is
emphasised, emphasis carries no information.

- No bold for stress, contrast, warning, or surprise.
- No capitalised words for stress: `NOT`, `ONE`, `NEVER`, `ALWAYS`, `TENANT`. Capitals are for
  acronyms, HTTP methods, environment variables, enum constants, and other identifiers that are
  genuinely spelled that way.
- No italics for stress. Italics mark a term quoted as a term, and little else.

Where a fact is important, give it its own sentence, its own paragraph, or its own heading. Position
carries emphasis in a reference manual; typography does not.

## Headings

A heading is an index entry and a link target. It labels the material beneath it.

- Write a noun phrase. "Scope resolution", not "`governanceRole` is read identically at both scopes,
  and the route is what distinguishes them".
- No commas, no conjunctions joining two clauses, no question forms, no verbs of judgement
  ("deliberately", "on purpose", "worth", "why").
- Eight words is the practical ceiling, and twelve is the limit, counting a code span as one word.
- Headings are link anchors. Renaming one is an interface change: every cross-reference to the old
  anchor is updated in the same commit.

## Justification

State what the system does. Explain a decision only where a reader who does not know it would draw a
wrong conclusion, and then explain it plainly, in its own sentence.

- Do not defend a design against an imagined objection. "That is deliberate rather than unfinished",
  "rather than an oversight" and "this is the design working" all answer a criticism nobody reading
  a manual has made.
- Do not certify a claim's provenance in passing. "Measured, not reasoned about", "read out of the
  source", "and none of it is hedged" and "stated as a position" are assurances about the author's
  diligence. Where provenance genuinely matters, such as a benchmark's conditions, it is content:
  give it a sentence that says what was measured, on what, and when.
- Do not write about the document. A document does not explain why it exists, why it is separate
  from another document, how many times it has been corrected, or what it is not. Routing belongs in
  the directory's entry point.

## Punctuation and mechanics

- No em dashes and no spaced double hyphens. Use a comma, a semicolon, a colon, parentheses, or
  two sentences.
- Use a serial comma.
- British spelling in prose: `behaviour`, `serialise`, `materialise`. Technical terms keep the
  spelling of the thing they name: the HTTP header is `Authorization`, and an identifier is quoted
  exactly as the source spells it.
- Code formatting for anything a machine reads: identifiers, file paths, property keys, environment
  variables, HTTP methods and paths, status codes, literal values.
- Wrap prose at 100 columns, matching the rest of the corpus.
- Tables take a header row that names the columns. A table is for material with a repeating shape;
  prose with pipes in it is not a table.

