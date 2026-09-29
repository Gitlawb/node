# GraphQL repository pagination

`repos` returns the complete visible repository list when it contains at most
200 entries. Larger lists return a GraphQL error directing the caller to
`reposPage`; they are never silently truncated.

Use `reposPage` for larger lists:

```graphql
query Repositories($after: String) {
  reposPage(limit: 50, after: $after) {
    nodes {
      name
      ownerDid
    }
    hasNextPage
    endCursor
  }
}
```

Start with `after: null`. When `hasNextPage` is true, pass the returned
`endCursor` as `after` on the next request. Stop when `hasNextPage` is false.
An empty page has a null `endCursor`. The default limit is 50 and the maximum
page size is 200; limits below 1 or above 200 are rejected (see Query budgets
below). Malformed cursors, including decoded owner or name strings containing
NUL, return `invalid repository cursor` before database access.

Pages are ordered by normalized owner DID and repository name. Visibility and
mirror deduplication are applied in the database before limiting the page;
hidden and quarantined repositories do not occupy page slots or create a
continuation signal. Cursors contain a position from the last returned visible
repository, not a permission grant. Each request checks the current caller's
visibility independently. Keep the same caller while traversing a list.
Malformed reader lists in a repository's root visibility rule deny access to
non-owners for that repository while other visible repositories remain listable.

Pagination is not a snapshot: concurrent renames, ownership changes, or visibility
changes can alter subsequent pages. Treat cursors as opaque and restart from the
first page when a fresh complete traversal is needed. Small legacy `repos`
queries retain their activity ordering.

## Query budgets

Every GraphQL document is validated against two budgets before any resolver
runs. Both apply per document (per request), not per client: `/graphql` has
no per-caller rate limiting, so a rejected document can always be retried
smaller. The constants live in `crates/gitlawb-node/src/graphql/mod.rs`.

- **Complexity budget: 400 per document** (`GRAPHQL_MAX_COMPLEXITY`). Each
  root field carries a base cost plus the clamped page size plus the selected
  child fields:
  - `repos`: 50 + `MAX_VISIBLE_REPO_PAGE_SIZE` + child fields. `repos`
    always scans the full visible corpus, so it is priced as the full page
    it is.
  - `reposPage`: 50 + `MAX_VISIBLE_REPO_PAGE_SIZE` + child fields. Every
    page request sorts the full deduplicated corpus, so the price does not
    depend on `limit`: seven `reposPage(limit: 1)` aliases cost the same as
    seven max-size pages.
  - `refUpdates`: 100 + clamped `limit` (`MAX_VISIBLE_REF_UPDATES`) + child
    fields. The 100 base covers the collector's fixed scan (the deduplicated
    repo set, the quarantined set, the visibility rules, and the bounded
    up-to-2048-row walk past withheld rows); the limit term prices only the
    rows returned.
  - `tasks`: 50 + clamped `limit` (`MAX_VISIBLE_TASK_PAGE_SIZE`) + child
    fields.
  - `task`, mutations, subscriptions: 50 + child fields.

  A document whose total exceeds 400 is rejected with
  `Query is too complex.` before any resolver runs, so an over-budget
  document needs fewer aliases or fewer child fields. A smaller `limit` does
  not help `reposPage` or `repos`: both are priced at the full
  `MAX_VISIBLE_REPO_PAGE_SIZE` scan regardless of `limit`.

- **Depth cap: 14 per document** (`GRAPHQL_MAX_DEPTH`). Documents nested
  deeper than 14 selections are rejected with `Query is nested too deep.`
