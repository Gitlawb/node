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
An empty page has a null `endCursor`. The default limit is 50; limits outside
1–200 are rejected. The document complexity budget still applies, so requesting
many fields may require a smaller page.

Pages are ordered by normalized owner DID and repository name. Visibility and
mirror deduplication are applied in the database before limiting the page;
hidden and quarantined repositories do not occupy page slots or create a
continuation signal. Cursors contain a position from the last returned visible
repository, not a permission grant. Each request checks the current caller's
visibility independently. Keep the same caller while traversing a list.

Pagination is not a snapshot: concurrent renames, ownership changes, or visibility
changes can alter subsequent pages. Treat cursors as opaque and restart from the
first page when a fresh complete traversal is needed. Small legacy `repos`
queries retain their activity ordering.
