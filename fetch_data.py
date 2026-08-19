#!/usr/bin/env python3
import json
import time
import base64
import ssl
import urllib.request
import urllib.parse
import os
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from statistics import median
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    import certifi
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CTX = ssl.create_default_context()

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "sprint_data.json")

NUM_SPRINTS = 4


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def github_graphql(token, query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        "https://api.github.com/graphql", data=body, method="POST"
    )
    req.add_header("Authorization", f"bearer {token}")
    req.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(req, context=SSL_CTX)
    return json.loads(resp.read())


def google_access_token(sa_key_path):
    with open(sa_key_path) as f:
        creds = json.load(f)

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=")
    now = int(time.time())
    claim_set = {
        "iss": creds["client_email"],
        "scope": "https://www.googleapis.com/auth/spreadsheets.readonly",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(claim_set).encode()
    ).rstrip(b"=")
    signing_input = header + b"." + payload_b64
    private_key = serialization.load_pem_private_key(
        creds["private_key"].encode(), password=None
    )
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
    jwt_token = (signing_input + b"." + sig_b64).decode()

    data = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt_token,
        }
    ).encode()
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token", data=data, method="POST"
    )
    resp = urllib.request.urlopen(req, context=SSL_CTX)
    return json.loads(resp.read())["access_token"]


def fetch_github_project(token, org, project_number):
    fields_query = """query {
      organization(login: "%s") {
        projectV2(number: %d) {
          title
          fields(first: 30) {
            nodes {
              ... on ProjectV2IterationField {
                id name
                configuration {
                  iterations { id title startDate duration }
                  completedIterations { id title startDate duration }
                }
              }
            }
          }
        }
      }
    }""" % (org, project_number)

    result = github_graphql(token, fields_query)
    project = result["data"]["organization"]["projectV2"]

    all_iterations = []
    for field in project["fields"]["nodes"]:
        if "configuration" in field:
            all_iterations = (
                field["configuration"]["iterations"]
                + field["configuration"]["completedIterations"]
            )
            break

    today = datetime.now().strftime("%Y-%m-%d")
    past_iterations = [s for s in all_iterations if s["startDate"] <= today]
    future_iterations = [s for s in all_iterations if s["startDate"] > today]
    past_iterations.sort(key=lambda x: x["startDate"], reverse=True)
    future_iterations.sort(key=lambda x: x["startDate"])
    target_sprints = past_iterations[:NUM_SPRINTS]
    upcoming_sprints = future_iterations[:2]
    if upcoming_sprints:
        target_sprints = target_sprints + [upcoming_sprints[0]]
    target_names = {s["title"] for s in target_sprints}

    items_query = """query($cursor: String) {
      organization(login: "%s") {
        projectV2(number: %d) {
          items(first: 100, after: $cursor) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes {
              fieldValues(first: 20) {
                nodes {
                  ... on ProjectV2ItemFieldIterationValue {
                    field { ... on ProjectV2IterationField { name } }
                    title
                  }
                  ... on ProjectV2ItemFieldSingleSelectValue {
                    field { ... on ProjectV2SingleSelectField { name } }
                    name
                  }
                  ... on ProjectV2ItemFieldNumberValue {
                    field { ... on ProjectV2Field { name } }
                    number
                  }
                }
              }
              content {
                ... on Issue {
                  title number state
                  labels(first:5) { nodes { name } }
                  assignees(first:3) { nodes { login } }
                  repository { name }
                }
                ... on PullRequest { title number state }
              }
            }
          }
        }
      }
    }""" % (org, project_number)

    all_items = []
    cursor = None
    while True:
        result = github_graphql(token, items_query, {"cursor": cursor})
        items_data = result["data"]["organization"]["projectV2"]["items"]

        for node in items_data["nodes"]:
            sprint_name = None
            status = None
            sprint_goal = None
            story_points = None
            priority = None

            for fv in node.get("fieldValues", {}).get("nodes", []):
                field_name = fv.get("field", {}).get("name", "")
                if field_name == "Sprint":
                    sprint_name = fv.get("title")
                elif field_name == "Status":
                    status = fv.get("name")
                elif field_name == "Sprint Goal":
                    sprint_goal = fv.get("name")
                elif field_name == "Story Points":
                    story_points = fv.get("number")
                elif field_name == "Priority":
                    priority = fv.get("name")

            if sprint_name in target_names:
                content = node.get("content", {})
                all_items.append(
                    {
                        "sprint": sprint_name,
                        "status": status,
                        "sprint_goal": sprint_goal,
                        "story_points": story_points,
                        "priority": priority,
                        "title": content.get("title"),
                        "number": content.get("number"),
                        "state": content.get("state"),
                        "repo": (
                            content.get("repository", {}).get("name")
                            if content.get("repository")
                            else None
                        ),
                        "assignees": (
                            [a["login"] for a in content.get("assignees", {}).get("nodes", [])]
                            if content.get("assignees")
                            else []
                        ),
                    }
                )

        if not items_data["pageInfo"]["hasNextPage"]:
            break
        cursor = items_data["pageInfo"]["endCursor"]

    sprint_summaries = {}
    for sprint_info in target_sprints:
        name = sprint_info["title"]
        si = [i for i in all_items if i["sprint"] == name]
        done = [i for i in si if i["status"] and "Done" in i["status"]]

        statuses = {}
        for i in si:
            s = i["status"] or "None"
            statuses[s] = statuses.get(s, 0) + 1

        goals = {}
        for i in si:
            g = i["sprint_goal"] or "Uncategorized"
            goals[g] = goals.get(g, 0) + 1

        priorities = {}
        for i in si:
            p = i["priority"] or "None"
            priorities[p] = priorities.get(p, 0) + 1

        assignees = {}
        for i in si:
            for a in i["assignees"]:
                assignees[a] = assignees.get(a, 0) + 1

        repos = {}
        for i in si:
            r = i["repo"] or "None"
            repos[r] = repos.get(r, 0) + 1

        sprint_summaries[name] = {
            "start_date": sprint_info["startDate"],
            "duration": sprint_info["duration"],
            "total_items": len(si),
            "done_items": len(done),
            "total_story_points": sum(i["story_points"] or 0 for i in si),
            "done_story_points": sum(i["story_points"] or 0 for i in done),
            "statuses": statuses,
            "goals": goals,
            "priorities": priorities,
            "assignees": dict(sorted(assignees.items(), key=lambda x: -x[1])[:15]),
            "repos": dict(sorted(repos.items(), key=lambda x: -x[1])),
        }

    return sprint_summaries, upcoming_sprints


def is_black(bg):
    if not bg:
        return True
    r = bg.get("red", 0)
    g = bg.get("green", 0)
    b = bg.get("blue", 0)
    return r < 0.2 and g < 0.2 and b < 0.2


def fetch_availability(config, sprint_names):
    access_token = google_access_token(config["google_sa_key_path"])
    sheet_id = config["google_sheet_id"]

    ranges = [urllib.parse.quote(s) for s in sprint_names]
    ranges_param = "&".join([f"ranges={r}" for r in ranges])

    url = (
        f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}"
        f"?{ranges_param}&includeGridData=true"
        f"&fields=sheets(properties(title),data(rowData(values(formattedValue,"
        f"effectiveFormat(backgroundColor,backgroundColorStyle)))))"
    )
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {access_token}")

    try:
        resp = urllib.request.urlopen(req, context=SSL_CTX)
    except urllib.error.HTTPError as e:
        print(f"Warning: Could not fetch some sheets: {e}", file=sys.stderr)
        return {}

    result = json.loads(resp.read())
    availability = {}

    for sheet in result.get("sheets", []):
        title = sheet["properties"]["title"]
        grid = sheet.get("data", [{}])[0]
        rows = grid.get("rowData", [])

        dates = []
        if len(rows) > 1:
            for cell in rows[1].get("values", [])[1:]:
                dates.append(cell.get("formattedValue", ""))

        total_days = len(dates)
        engineers = {}

        for row_idx in range(2, len(rows)):
            row = rows[row_idx]
            cells = row.get("values", [])
            if not cells:
                continue
            name = cells[0].get("formattedValue", "").strip()
            if not name:
                continue

            ooo_count = 0
            for col_idx, cell in enumerate(cells[1:], 0):
                bg_style = (
                    cell.get("effectiveFormat", {})
                    .get("backgroundColorStyle", {})
                    .get("rgbColor", None)
                )
                bg = cell.get("effectiveFormat", {}).get("backgroundColor", None)

                if (bg_style is not None and is_black(bg_style)) or (
                    bg is not None and is_black(bg)
                ):
                    ooo_count += 1

            engineers[name] = {
                "ooo_days": ooo_count,
                "available_days": total_days - ooo_count,
            }

        eng_count = len(engineers)
        total_capacity = eng_count * total_days
        total_ooo = sum(e["ooo_days"] for e in engineers.values())

        availability[title] = {
            "total_working_days": total_days,
            "engineer_count": eng_count,
            "total_ooo_days": total_ooo,
            "total_available_days": total_capacity - total_ooo,
            "total_capacity_days": total_capacity,
            "capacity_pct": (
                round((total_capacity - total_ooo) / total_capacity * 100, 1)
                if total_capacity
                else 0
            ),
            "engineers": engineers,
        }

    return availability


TEAMS = {
    "Podman Desktop": [
        "Stevan", "Jiri", "Florent", "Philippe", "Simon", "Vlad",
        "Vaclav", "Tim", "Shipra",
    ],
    "Red Hat build of Podman Desktop": [
        "Rujuta", "Charlie", "Ondrej", "Axel", "Denis", "Sonia",
    ],
    "Kaiden": [
        "Jeff", "George", "Brian", "Marcel", "Evzen",
    ],
    "QE": [
        "Anton", "Daniel Villanueva", "Tibor", "Vladimir L",
    ],
}

MEMBER_TO_TEAM = {}
for _team, _members in TEAMS.items():
    for _m in _members:
        MEMBER_TO_TEAM[_m] = _team


def add_team_capacity(availability):
    for sn, sprint_avail in availability.items():
        teams = {}
        for eng_name, eng_data in sprint_avail["engineers"].items():
            team = MEMBER_TO_TEAM.get(eng_name, "Other")
            if team not in teams:
                teams[team] = {"members": [], "ooo_days": 0, "available_days": 0}
            teams[team]["members"].append(eng_name)
            teams[team]["ooo_days"] += eng_data["ooo_days"]
            teams[team]["available_days"] += eng_data["available_days"]

        total_days = sprint_avail["total_working_days"]
        for team, td in teams.items():
            member_count = len(td["members"])
            total_capacity = member_count * total_days
            td["member_count"] = member_count
            td["capacity_pct"] = (
                round((total_capacity - td["ooo_days"]) / total_capacity * 100, 1)
                if total_capacity else 0
            )
        sprint_avail["teams"] = teams


DOMAIN_OWNERS = {
    "extensibility": ["benoitf", "deboer-tim"],
    "ui-components": ["vancura", "benoitf"],
    "kubernetes": ["cdrage", "gastoner"],
    "containers": ["axel7083", "benoitf"],
    "foundations": ["benoitf", "deboer-tim"],
    "docs": ["kyetter", "slemeur", "cdrage", "ShiranHi"],
    "technical-debt": ["axel7083", "gastoner"],
    "ci-cd": ["odockal", "axel7083"],
    "networking": ["SoniaSandler", "axel7083"],
    "settings": ["adameska", "cdrage"],
    "cli-tool": ["simonrey1", "adameska"],
    "qe": ["amisskii", "danivilla9", "serbangeorge-m", "odockal", "ScrewTSW", "vzhukovs"],
    "catalog": ["benoitf"],
    "github-actions": ["benoitf"],
    "kubernetes-dashboard": ["jeffmaury", "gastoner"],
    "kubernetes-context": ["jeffmaury", "gastoner"],
    "kubernetes-contexts": ["jeffmaury", "gastoner"],
    "kubernetes-pack": ["jeffmaury", "gastoner"],
    "podman-quadlet": ["axel7083", "benoitf"],
    "bootc": ["cdrage", "deboer-tim"],
    "postgresql": ["jeffmaury", "gastoner"],
    "layers-explorer": ["jeffmaury", "gastoner"],
    "apple-container": ["benoitf"],
    "github": ["dgolovin", "SoniaSandler"],
    "kreate": ["cdrage", "gastoner"],
    "kind": ["benoitf", "SoniaSandler"],
    "compose": ["benoitf", "jeffmaury"],
    "minikube": ["benoitf", "jeffmaury"],
    "ai-sandbox": ["axel7083", "benoitf"],
    "hummingbird": ["axel7083", "benoitf"],
    "rhel": ["gastoner", "SoniaSandler"],
    "ibmcloud-account": ["benoitf", "dgolovin"],
    "redhat-account": ["dgolovin", "SoniaSandler"],
    "sandbox": ["dgolovin", "jeffmaury"],
    "image-checker-openshift": ["jeffmaury", "gastoner"],
    "redhat-lightspeed": ["benoitf", "jeffmaury"],
    "enterprise-sso": ["dgolovin", "benoitf"],
    "crc": ["jeffmaury", "SoniaSandler"],
    "minc": ["benoitf", "SoniaSandler"],
    "ai-lab": ["bmahabirbu", "jeffmaury"],
    "grype": ["axel7083", "simonrey1"],
    "redhat-pack": ["benoitf", "jeffmaury"],
}

BOT_AUTHORS = {
    "dependabot", "dependabot[bot]", "coderabbitai", "coderabbitai[bot]",
    "podman-desktop-bot", "podman-desktop-bot[bot]", "renovate",
    "renovate[bot]", "github-actions", "github-actions[bot]",
    "mergify", "mergify[bot]",
}


def parse_iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def hours_between(a, b):
    return round((parse_iso(b) - parse_iso(a)).total_seconds() / 3600, 2)


def business_days_between(a, b):
    start = parse_iso(a).date()
    end = parse_iso(b).date()
    if end < start:
        return 0.0
    days = 0
    current = start
    while current <= end:
        if current.weekday() < 5:
            days += 1
        current += timedelta(days=1)
    if days > 0:
        days -= 1
    start_dt = parse_iso(a)
    end_dt = parse_iso(b)
    if start.weekday() < 5:
        start_frac = (24 - start_dt.hour - start_dt.minute / 60) / 24
    else:
        start_frac = 0
    if end.weekday() < 5:
        end_frac = (end_dt.hour + end_dt.minute / 60) / 24
    else:
        end_frac = 0
    return round(max(0, days + start_frac + end_frac - 1), 2)


def is_sprint_frozen(start_date, duration):
    eastern = ZoneInfo("America/New_York")
    last_day = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=eastern)
    freeze_cutoff = last_day + timedelta(days=duration - 1, hours=12)
    now = datetime.now(eastern)
    return now >= freeze_cutoff


def extract_domain(labels):
    for lbl in labels:
        if lbl.startswith("domain/"):
            parts = lbl.split("/")
            if len(parts) >= 2:
                return parts[1]
    return None


def date_in_sprint(date_str, sprint_start, sprint_duration):
    d = datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
    start = datetime.strptime(sprint_start, "%Y-%m-%d").date()
    end = start + timedelta(days=sprint_duration)
    return start <= d < end


def fetch_pr_data(token, org, sprint_windows):
    earliest = min(s["startDate"] for s in sprint_windows)

    repos_query = """query($cursor: String) {
      organization(login: "%s") {
        repositories(first: 50, after: $cursor) {
          pageInfo { hasNextPage endCursor }
          nodes { name }
        }
      }
    }""" % org

    repo_names = []
    cursor = None
    while True:
        result = github_graphql(token, repos_query, {"cursor": cursor})
        repos_data = result["data"]["organization"]["repositories"]
        repo_names.extend(r["name"] for r in repos_data["nodes"])
        if not repos_data["pageInfo"]["hasNextPage"]:
            break
        cursor = repos_data["pageInfo"]["endCursor"]

    pr_query = """query($owner: String!, $repo: String!, $cursor: String) {
      repository(owner: $owner, name: $repo) {
        pullRequests(first: 50, after: $cursor, orderBy: {field: CREATED_AT, direction: DESC}) {
          pageInfo { hasNextPage endCursor }
          nodes {
            number title state createdAt mergedAt closedAt isDraft
            author { login }
            labels(first: 15) { nodes { name } }
            reviews(first: 50) {
              nodes {
                author { login }
                state
                createdAt
              }
            }
          }
        }
      }
    }"""

    all_prs = []
    for repo_name in repo_names:
        cursor = None
        done = False
        while not done:
            result = github_graphql(token, pr_query, {
                "owner": org, "repo": repo_name, "cursor": cursor,
            })
            repo_data = result.get("data", {}).get("repository")
            if not repo_data:
                break
            pr_data = repo_data["pullRequests"]
            for pr in pr_data["nodes"]:
                if not pr.get("author"):
                    continue
                created = pr["createdAt"][:10]
                if created < earliest:
                    done = True
                    break

                author = pr["author"]["login"]
                labels = [l["name"] for l in pr.get("labels", {}).get("nodes", [])]
                reviews = []
                for rv in pr.get("reviews", {}).get("nodes", []):
                    if not rv.get("author"):
                        continue
                    rv_author = rv["author"]["login"]
                    if rv_author.lower() in BOT_AUTHORS or rv_author == author:
                        continue
                    reviews.append({
                        "author": rv_author,
                        "state": rv["state"],
                        "created_at": rv["createdAt"],
                    })

                all_prs.append({
                    "repo": repo_name,
                    "number": pr["number"],
                    "title": pr["title"],
                    "state": pr["state"],
                    "created_at": pr["createdAt"],
                    "merged_at": pr.get("mergedAt"),
                    "is_draft": pr.get("isDraft", False),
                    "author": author,
                    "is_bot": author.lower() in BOT_AUTHORS,
                    "labels": labels,
                    "domain": extract_domain(labels),
                    "reviews": reviews,
                })

            if not pr_data["pageInfo"]["hasNextPage"]:
                break
            cursor = pr_data["pageInfo"]["endCursor"]

    return all_prs


def compute_pr_metrics(all_prs, sprint_windows):
    metrics = {}

    for sw in sprint_windows:
        sprint_name = sw["title"]
        start = sw["startDate"]
        duration = sw["duration"]

        sprint_prs = [
            p for p in all_prs
            if not p["is_bot"] and date_in_sprint(p["created_at"], start, duration)
        ]

        merged = [p for p in sprint_prs if p["merged_at"]]

        times_to_first_review = []
        times_to_first_comment = []
        times_to_merge = []
        times_to_address = []

        for pr in sprint_prs:
            human_reviews = sorted(pr["reviews"], key=lambda r: r["created_at"])
            if human_reviews:
                t = hours_between(pr["created_at"], human_reviews[0]["created_at"])
                times_to_first_review.append(t)

            comment_reviews = [
                r for r in human_reviews
                if r["state"] in ("COMMENTED", "CHANGES_REQUESTED")
            ]
            if comment_reviews:
                t = hours_between(pr["created_at"], comment_reviews[0]["created_at"])
                times_to_first_comment.append(t)

            changes_requested = [
                r for r in human_reviews if r["state"] == "CHANGES_REQUESTED"
            ]
            if changes_requested and pr["merged_at"]:
                last_cr = max(r["created_at"] for r in changes_requested)
                later_events = [
                    r for r in human_reviews
                    if r["created_at"] > last_cr and r["author"] != pr["author"]
                ]
                if later_events:
                    t = hours_between(last_cr, later_events[0]["created_at"])
                    times_to_address.append(t)

        for pr in merged:
            t = hours_between(pr["created_at"], pr["merged_at"])
            times_to_merge.append(t)

        def stats(vals):
            if not vals:
                return {"avg": 0, "median": 0, "count": 0}
            return {
                "avg": round(sum(vals) / len(vals), 1),
                "median": round(median(vals), 1),
                "count": len(vals),
            }

        # Weekly extremes
        weekly = {}
        for pr in merged:
            iso_week = parse_iso(pr["merged_at"]).strftime("%Y-W%W")
            merge_time = hours_between(pr["created_at"], pr["merged_at"])
            if iso_week not in weekly:
                weekly[iso_week] = {"longest": None, "shortest": None}
            entry = {
                "title": pr["title"],
                "repo": pr["repo"],
                "number": pr["number"],
                "hours": merge_time,
            }
            if weekly[iso_week]["longest"] is None or merge_time > weekly[iso_week]["longest"]["hours"]:
                weekly[iso_week]["longest"] = entry
            if weekly[iso_week]["shortest"] is None or merge_time < weekly[iso_week]["shortest"]["hours"]:
                weekly[iso_week]["shortest"] = entry

        # Per-author merged PR count
        author_merged = {}
        for pr in merged:
            a = pr["author"]
            author_merged[a] = author_merged.get(a, 0) + 1

        # Reviewer activity
        reviewer_approvals = {}
        reviewer_approval_bdays = {}
        for pr in sprint_prs:
            for rv in pr["reviews"]:
                if rv["state"] == "APPROVED":
                    a = rv["author"]
                    reviewer_approvals[a] = reviewer_approvals.get(a, 0) + 1
                    bd = business_days_between(pr["created_at"], rv["created_at"])
                    if a not in reviewer_approval_bdays:
                        reviewer_approval_bdays[a] = []
                    reviewer_approval_bdays[a].append(bd)

        engineer_avg_approval = {}
        for eng, bdays in reviewer_approval_bdays.items():
            engineer_avg_approval[eng] = round(sum(bdays) / len(bdays), 2) if bdays else 0

        # Domain metrics
        domain_prs = {}
        domain_approvals = {}
        domain_approval_times = {}
        for pr in sprint_prs:
            d = pr["domain"]
            if not d:
                continue
            domain_prs[d] = domain_prs.get(d, 0) + 1

            for rv in pr["reviews"]:
                if rv["state"] == "APPROVED":
                    if d not in domain_approvals:
                        domain_approvals[d] = {}
                    a = rv["author"]
                    domain_approvals[d][a] = domain_approvals[d].get(a, 0) + 1

                    t = hours_between(pr["created_at"], rv["created_at"])
                    if d not in domain_approval_times:
                        domain_approval_times[d] = []
                    domain_approval_times[d].append(t)

        domain_owner_authored = {}
        for pr in sprint_prs:
            d = pr["domain"]
            if not d:
                continue
            owners = DOMAIN_OWNERS.get(d)
            if owners and pr["author"] in owners:
                domain_owner_authored[d] = domain_owner_authored.get(d, 0) + 1

        domain_ownership = {}
        for d, approvers in domain_approvals.items():
            owners = DOMAIN_OWNERS.get(d)
            if owners:
                filtered = {a: c for a, c in approvers.items() if a in owners}
            else:
                filtered = approvers
            total = sum(filtered.values()) if filtered else 1
            domain_ownership[d] = {
                a: round(c / total * 100, 1) for a, c in
                sorted(filtered.items(), key=lambda x: -x[1])
            }

        domain_avg_approval = {}
        for d, times in domain_approval_times.items():
            domain_avg_approval[d] = round(sum(times) / len(times), 1) if times else 0

        metrics[sprint_name] = {
            "total_prs": len(sprint_prs),
            "merged_prs": len(merged),
            "time_to_first_review": stats(times_to_first_review),
            "time_to_first_comment": stats(times_to_first_comment),
            "time_to_merge": stats(times_to_merge),
            "time_to_address_comments": stats(times_to_address),
            "weekly_extremes": dict(sorted(weekly.items())),
            "author_merged_prs": dict(
                sorted(author_merged.items(), key=lambda x: -x[1])
            ),
            "reviewer_approvals": dict(
                sorted(reviewer_approvals.items(), key=lambda x: -x[1])
            ),
            "domain_pr_count": dict(sorted(domain_prs.items(), key=lambda x: -x[1])),
            "domain_owner_authored": dict(sorted(domain_owner_authored.items(), key=lambda x: -x[1])),
            "domain_approval_ownership": domain_ownership,
            "domain_avg_approval_hours": domain_avg_approval,
            "engineer_avg_approval_bdays": dict(
                sorted(engineer_avg_approval.items(), key=lambda x: x[1])
            ),
        }

    # Rolling 3-month domain approval ownership (with and without bot PRs)
    cutoff = datetime.now().astimezone() - timedelta(days=90)
    rolling = {}
    for include_bots in (False, True):
        suffix = "_all" if include_bots else ""
        recent_prs = [
            p for p in all_prs
            if parse_iso(p["created_at"]) >= cutoff
            and (include_bots or not p["is_bot"])
        ]
        r_domain_prs = {}
        r_domain_approvals = {}
        for pr in recent_prs:
            d = pr["domain"]
            if not d:
                continue
            r_domain_prs[d] = r_domain_prs.get(d, 0) + 1
            for rv in pr["reviews"]:
                if rv["state"] == "APPROVED":
                    if d not in r_domain_approvals:
                        r_domain_approvals[d] = {}
                    a = rv["author"]
                    r_domain_approvals[d][a] = r_domain_approvals[d].get(a, 0) + 1

        r_domain_ownership = {}
        for d, approvers in r_domain_approvals.items():
            owners = DOMAIN_OWNERS.get(d)
            if owners:
                filtered = {a: c for a, c in approvers.items() if a in owners}
            else:
                filtered = approvers
            total = sum(filtered.values()) if filtered else 1
            r_domain_ownership[d] = {
                a: round(c / total * 100, 1) for a, c in
                sorted(filtered.items(), key=lambda x: -x[1])
            }
        rolling[f"rolling_domain_ownership{suffix}"] = r_domain_ownership
        rolling[f"rolling_domain_pr_count{suffix}"] = dict(
            sorted(r_domain_prs.items(), key=lambda x: -x[1])
        )

    # Draft PRs snapshot (current state, not per-sprint)
    draft_prs = {}
    for pr in all_prs:
        if pr["is_draft"] and pr["state"] == "OPEN" and not pr["is_bot"]:
            a = pr["author"]
            if a not in draft_prs:
                draft_prs[a] = []
            draft_prs[a].append({
                "repo": pr["repo"],
                "number": pr["number"],
                "title": pr["title"],
                "created_at": pr["created_at"],
            })

    return {"sprints": metrics, "draft_prs": draft_prs, **rolling}


def main():
    config = load_config()
    token = config["github_token"]

    previous_data = None
    if os.path.exists(OUTPUT_PATH):
        try:
            with open(OUTPUT_PATH) as f:
                previous_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            previous_data = None

    all_project_data = {}
    all_sprint_data = {}
    all_sprint_names = set()
    all_upcoming = []

    for proj in config["projects"]:
        name = proj["name"]
        org = proj["github_org"]
        num = proj["github_project_number"]
        print(f"Fetching GitHub project data for {name} ({org}/projects/{num})...")
        sprint_data, upcoming = fetch_github_project(token, org, num)
        all_sprint_data[name] = sprint_data
        all_sprint_names.update(sprint_data.keys())
        if upcoming and not all_upcoming:
            all_upcoming = upcoming

    sprint_names = sorted(all_sprint_names)
    upcoming_names = [s["title"] for s in all_upcoming]
    print(f"Found sprints: {sprint_names}")
    if upcoming_names:
        print(f"Upcoming sprints: {upcoming_names}")

    # Collect sprint windows from the first project for date ranges
    first_proj = config["projects"][0]
    first_sprint_data = all_sprint_data[first_proj["name"]]
    sprint_windows = [
        {"title": sn, "startDate": first_sprint_data[sn]["start_date"], "duration": first_sprint_data[sn]["duration"]}
        for sn in sprint_names if sn in first_sprint_data
    ]

    # Fetch PR data for each org
    for proj in config["projects"]:
        name = proj["name"]
        org = proj["github_org"]
        print(f"Fetching PR data for {name} ({org})...")
        prs = fetch_pr_data(token, org, sprint_windows)
        print(f"  Found {len(prs)} PRs in window")
        pr_metrics = compute_pr_metrics(prs, sprint_windows)
        all_project_data[name] = {
            "github_org": org,
            "sprints": all_sprint_data[name],
            "pr_metrics": pr_metrics,
        }

    # Freeze completed sprints to preserve data when issues are moved
    print("Checking sprint freeze status...")
    for name, proj_data in all_project_data.items():
        prev_proj = (previous_data or {}).get("projects", {}).get(name, {})
        prev_sprints = prev_proj.get("sprints", {})
        prev_pr_sprints = prev_proj.get("pr_metrics", {}).get("sprints", {})

        for sn, sd in list(proj_data["sprints"].items()):
            if sn in prev_sprints and prev_sprints[sn].get("frozen_at"):
                proj_data["sprints"][sn] = prev_sprints[sn]
                if sn in prev_pr_sprints:
                    proj_data["pr_metrics"]["sprints"][sn] = prev_pr_sprints[sn]
                print(f"  {sn}: frozen (preserved from {prev_sprints[sn]['frozen_at']})")
                continue

            if is_sprint_frozen(sd["start_date"], sd["duration"]):
                if sn in prev_sprints and not prev_sprints[sn].get("frozen_at"):
                    proj_data["sprints"][sn] = prev_sprints[sn]
                proj_data["sprints"][sn]["frozen_at"] = datetime.now().isoformat()
                print(f"  {sn}: freezing now")

    print("Fetching Google Sheets availability data...")
    availability = fetch_availability(config, sprint_names)
    add_team_capacity(availability)

    projected_availability = {}
    if upcoming_names:
        print(f"Fetching projected availability for {upcoming_names}...")
        projected_availability = fetch_availability(config, upcoming_names)
        add_team_capacity(projected_availability)

    upcoming_info = [
        {"title": s["title"], "start_date": s["startDate"], "duration": s["duration"]}
        for s in all_upcoming
    ]

    output = {
        "generated_at": datetime.now().isoformat(),
        "projects": all_project_data,
        "availability": availability,
        "projected_availability": projected_availability,
        "upcoming_sprints": upcoming_info,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Data written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
