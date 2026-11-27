#!/usr/bin/env bash
# Merge Velocidex/velociraptor master into this fork and open a sync PR.
#
# Branches:
#   upstream-master  exact mirror of upstream master (never commit here)
#   sync/upstream    master + merge of upstream-master, the PR head
#
# Paths listed in KEEP_OURS are always kept at our version during the
# merge. Upstream commits touching them are listed in the PR body so
# they can be ported by hand.
set -euo pipefail

UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/Velocidex/velociraptor.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-master}"
BASE="${BASE:-master}"
MIRROR="${MIRROR:-upstream-master}"
SYNC="${SYNC:-sync/upstream}"
KEEP_OURS="${KEEP_OURS:-gui/velociraptor README.md CONTRIBUTING.md security.md}"
DRY_RUN="${DRY_RUN:-}"

git config user.name  "${GIT_AUTHOR_NAME:-github-actions[bot]}"
git config user.email "${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"

git fetch --no-tags origin "$BASE"
git fetch --no-tags "$UPSTREAM_URL" "$UPSTREAM_BRANCH"
UPSTREAM_SHA=$(git rev-parse FETCH_HEAD)
BASE_SHA=$(git rev-parse "origin/$BASE")

# 1. Keep the mirror branch identical to upstream.
if [ -z "$DRY_RUN" ]; then
  git push --force origin "$UPSTREAM_SHA:refs/heads/$MIRROR"
fi

if git merge-base --is-ancestor "$UPSTREAM_SHA" "$BASE_SHA"; then
  echo "$BASE already contains upstream ${UPSTREAM_SHA:0:12}. Nothing to do."
  exit 0
fi

RANGE="$BASE_SHA..$UPSTREAM_SHA"
COUNT=$(git rev-list --count "$RANGE")
SHORT=${UPSTREAM_SHA:0:12}

# 2. Merge upstream into a fresh sync branch.
git checkout -q -B "$SYNC" "$BASE_SHA"
git merge --no-ff --no-commit "$UPSTREAM_SHA" >/dev/null 2>&1 || true

for p in $KEEP_OURS; do
  if git cat-file -e "$BASE_SHA:$p" 2>/dev/null; then
    # Restore our tree for this path, dropping files upstream added there.
    git rm -r -q --cached --ignore-unmatch -- "$p"
    rm -rf -- "$p"
    git checkout "$BASE_SHA" -- "$p"
  fi
done

CONFLICTS=$(git diff --name-only --diff-filter=U)
HEAD_BRANCH="$SYNC"
if [ -n "$CONFLICTS" ]; then
  echo "Merge has conflicts outside kept paths:"; echo "$CONFLICTS"
  git merge --abort
  git checkout -q "$BASE_SHA"
  HEAD_BRANCH="$MIRROR"
else
  git commit -q --no-edit -m "Merge upstream Velociraptor ${SHORT}" \
    -m "Merges ${UPSTREAM_URL} ${UPSTREAM_BRANCH} at ${UPSTREAM_SHA}." \
    -m "Kept our version of: ${KEEP_OURS}"
fi

# 3. Build the PR body.
BODY=$(mktemp)
{
  echo "Merges **${COUNT}** new upstream commits (up to [\`${SHORT}\`](https://github.com/Velocidex/velociraptor/commit/${UPSTREAM_SHA}))."
  echo
  echo "> Merge this PR with a **merge commit**. Squash or rebase breaks the shared history and the next sync will re-apply everything."
  echo
  if [ -n "$CONFLICTS" ]; then
    echo "### ⚠️ Conflicts need manual resolution"
    echo "Automatic merge failed, so this PR comes straight from \`${MIRROR}\`. Resolve locally:"
    echo '```'
    echo "git fetch origin && git checkout -B ${SYNC} origin/${BASE}"
    echo "git merge origin/${MIRROR}"
    echo "git checkout origin/${BASE} -- ${KEEP_OURS}   # keep our GUI"
    echo "# fix the files below, commit, push, and open the PR from ${SYNC}"
    echo '```'
    echo "$CONFLICTS" | sed 's/^/- `/; s/$/`/'
    echo
  fi
  for p in $KEEP_OURS; do
    LIST=$(git log --no-merges --format='- [ ] [`%h`](https://github.com/Velocidex/velociraptor/commit/%H) %s' "$RANGE" -- "$p")
    if [ -n "$LIST" ]; then
      echo "### Upstream changes to \`$p\` (not merged, port by hand if needed)"
      echo "$LIST"
      echo
    fi
  done
  echo "<details><summary>All upstream commits</summary>"
  echo
  git log --no-merges --format='- [`%h`](https://github.com/Velocidex/velociraptor/commit/%H) %s' "$RANGE" | head -500
  echo
  echo "</details>"
} > "$BODY"

if [ -n "$DRY_RUN" ]; then
  cat "$BODY"; exit 0
fi

if [ "$HEAD_BRANCH" = "$SYNC" ]; then
  git push --force origin "$SYNC"
fi

TITLE="Sync upstream Velociraptor (${SHORT})"
EXISTING=$(gh pr list --base "$BASE" --head "$HEAD_BRANCH" --state open --json number --jq '.[0].number // empty')
if [ -n "$EXISTING" ]; then
  gh pr edit "$EXISTING" --title "$TITLE" --body-file "$BODY"
else
  # Close a stale sync PR from the other head branch, if any.
  OTHER=$([ "$HEAD_BRANCH" = "$SYNC" ] && echo "$MIRROR" || echo "$SYNC")
  for n in $(gh pr list --base "$BASE" --head "$OTHER" --state open --json number --jq '.[].number'); do
    gh pr close "$n" --comment "Superseded by a newer upstream sync."
  done
  gh pr create --base "$BASE" --head "$HEAD_BRANCH" --title "$TITLE" --body-file "$BODY" --label upstream-sync 2>/dev/null \
    || gh pr create --base "$BASE" --head "$HEAD_BRANCH" --title "$TITLE" --body-file "$BODY"
fi
