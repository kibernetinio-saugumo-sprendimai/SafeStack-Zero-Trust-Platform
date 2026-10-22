"""Command line interface for SafeStack Zero Trust Platform."""
import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from .api import serve
from .engine import evaluate
from .identity import authenticate, create_user
from .policy import load as load_policy_file
from .signing import keygen
from .store import Store
from .supply_chain import write_sbom


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line parser."""
    parser = argparse.ArgumentParser(
        prog="safestack-zt",
        description="SafeStack Zero Trust Platform CLI - Local-first security and policy engine",
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # device-add
    d = subparsers.add_parser("device-add", help="Register a new device in the inventory")
    d.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    d.add_argument("--id", default=None, help="Optional unique device identifier")
    d.add_argument("--name", required=True, help="Human-readable device name")
    d.add_argument("--owner", required=True, help="Device owner or user")
    d.add_argument(
        "--posture",
        choices=["unknown", "degraded", "compliant"],
        default="unknown",
        help="Device security posture state",
    )

    # policy-add
    pol = subparsers.add_parser("policy-add", help="Register an authorization policy")
    pol.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    pol.add_argument("--id", default=None, help="Optional unique policy identifier")
    pol.add_argument("--effect", choices=["allow", "deny"], required=True, help="Policy access effect")
    pol.add_argument("--subject", required=True, help="Target identity or '*'")
    pol.add_argument("--resource", required=True, help="Target resource or '*'")
    pol.add_argument("--action", required=True, help="Target action or '*'")
    pol.add_argument(
        "--min-posture",
        choices=["unknown", "degraded", "compliant"],
        default="compliant",
        help="Minimum required device posture",
    )

    # policy-load
    pload = subparsers.add_parser("policy-load", help="Load and register policies from a JSON file")
    pload.add_argument("file", help="Path to policy JSON file")
    pload.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")

    # authorize
    e = subparsers.add_parser("authorize", help="Evaluate an access request")
    e.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    e.add_argument("--device", required=True, help="Device ID")
    e.add_argument("--subject", required=True, help="Subject/User ID")
    e.add_argument("--resource", required=True, help="Target resource")
    e.add_argument("--action", required=True, help="Target action")

    # keygen
    k = subparsers.add_parser("keygen", help="Generate Ed25519 signing keypair")
    k.add_argument("private", help="Private key output file (0600)")
    k.add_argument("public", help="Public key output file (0644)")

    # user-add
    u = subparsers.add_parser("user-add", help="Add user identity to store")
    u.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    u.add_argument("--username", required=True, help="Username")
    u.add_argument("--password", required=True, help="Password (min 12 chars)")

    # user-auth
    ua = subparsers.add_parser("user-auth", help="Verify user identity credentials")
    ua.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    ua.add_argument("--username", required=True, help="Username")
    ua.add_argument("--password", required=True, help="Password")

    # sbom
    sb = subparsers.add_parser("sbom", help="Generate CycloneDX SBOM for a directory")
    sb.add_argument("root", help="Root directory to scan")
    sb.add_argument("output", help="Output JSON path")

    # serve
    v = subparsers.add_parser("serve", help="Start local dashboard and API")
    v.add_argument("--db", default="zero-trust.db", help="Path to SQLite database")
    v.add_argument("--host", default="127.0.0.1", help="Binding host")
    v.add_argument("--port", type=int, default=8787, help="Listening port")
    v.add_argument("--allow-remote", action="store_true", help="Allow remote bindings")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Execute SafeStack Zero Trust CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        keygen(args.private, args.public)
        print(f"Keypair generated: {args.private} (private), {args.public} (public)")
        return 0

    if args.cmd == "sbom":
        write_sbom(args.root, args.output)
        print(f"SBOM written to {args.output}")
        return 0

    if args.cmd == "serve":
        serve(db_path=args.db, host=args.host, port=args.port, allow_remote=args.allow_remote)
        return 0

    with Store(args.db) as db:
        if args.cmd == "device-add":
            device_id = args.id or str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            db.add_device((device_id, args.name, args.owner, args.posture, now))
            print("device registered")
            return 0

        if args.cmd == "policy-add":
            policy_id = args.id or str(uuid.uuid4())
            db.add_policy((policy_id, args.effect, args.subject, args.resource, args.action, args.min_posture))
            print("policy registered")
            return 0

        if args.cmd == "policy-load":
            policies = load_policy_file(args.file)
            for pol in policies:
                db.add_policy((
                    pol["id"],
                    pol["effect"],
                    pol["subject"],
                    pol["resource"],
                    pol["action"],
                    pol["min_posture"],
                ))
            print(f"loaded {len(policies)} policies into database")
            return 0

        if args.cmd == "user-add":
            create_user(db, args.username, args.password)
            print(f"user '{args.username}' created")
            return 0

        if args.cmd == "user-auth":
            ok = authenticate(db, args.username, args.password)
            if ok:
                print("authenticated: SUCCESS")
                return 0
            else:
                print("authenticated: FAILED")
                return 1

        if args.cmd == "authorize":
            result = evaluate(db, args.device, args.subject, args.resource, args.action)
            print(json.dumps(result.as_dict(), indent=2))
            return 0 if result.allowed else 2

    return 1


if __name__ == "__main__":
    sys.exit(main())
