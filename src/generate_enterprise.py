
"""PRIORIS Phase 2: Generate a reproducible synthetic enterprise.

Creates:
  data/synthetic/enterprise_assets.csv
  data/synthetic/software_inventory.csv

All generated enterprise assets and installations are simulated.
CPE identifiers are candidate product identifiers, not proof of vulnerability.
"""

import argparse
import csv
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data" / "synthetic"

# Candidate software products and illustrative installed versions.
# Validate CPE identifiers and affected-version ranges against NVD
# before using them for vulnerability matching.
SOFTWARE = {
    "apache_http": {
        "vendor": "apache",
        "product": "http_server",
        "name": "Apache HTTP Server",
        "versions": ["2.4.49", "2.4.50", "2.4.57", "2.4.62"],
    },
    "nginx": {
        "vendor": "nginx",
        "product": "nginx",
        "name": "NGINX",
        "versions": ["1.18.0", "1.20.0", "1.24.0", "1.26.0"],
    },
    "openssl": {
        "vendor": "openssl",
        "product": "openssl",
        "name": "OpenSSL",
        "versions": ["1.1.1k", "1.1.1w", "3.0.7", "3.0.13"],
    },
    "php": {
        "vendor": "php",
        "product": "php",
        "name": "PHP",
        "versions": ["7.4.33", "8.0.12", "8.1.0", "8.2.12"],
    },
    "wordpress": {
        "vendor": "wordpress",
        "product": "wordpress",
        "name": "WordPress",
        "versions": ["5.8", "5.9.3", "6.0", "6.4.2"],
    },
    "postgresql": {
        "vendor": "postgresql",
        "product": "postgresql",
        "name": "PostgreSQL",
        "versions": ["12.8", "13.3", "14.5", "15.4"],
    },
    "mysql": {
        "vendor": "oracle",
        "product": "mysql",
        "name": "MySQL",
        "versions": ["8.0.25", "8.0.28", "8.0.34", "8.4.0"],
    },
    "redis": {
        "vendor": "redis",
        "product": "redis",
        "name": "Redis",
        "versions": ["6.2.6", "6.2.14", "7.0.5", "7.2.4"],
    },
    "django": {
        "vendor": "djangoproject",
        "product": "django",
        "name": "Django",
        "versions": ["3.2.6", "3.2.25", "4.1.0", "4.2.8"],
    },
    "tomcat": {
        "vendor": "apache",
        "product": "tomcat",
        "name": "Apache Tomcat",
        "versions": ["9.0.50", "9.0.75", "9.0.85", "10.1.17"],
    },
    "jquery": {
        "vendor": "jquery",
        "product": "jquery",
        "name": "jQuery",
        "versions": ["3.5.1", "3.6.0", "3.7.0", "3.7.1"],
    },
    "nodejs": {
        "vendor": "nodejs",
        "product": "node.js",
        "name": "Node.js",
        "versions": ["14.17.0", "16.20.2", "18.18.2", "20.11.0"],
    },
}

# Each profile defines plausible software for a simulated asset type.
PROFILES = {
    "web_server": {
        "weight": 16,
        "criticality": (["critical", "high", "medium"], [20, 65, 15]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [85, 13, 2],
        ),
        "software": [
            "apache_http", "nginx", "openssl", "php",
            "wordpress", "jquery",
        ],
    },
    "database_server": {
        "weight": 14,
        "criticality": (["critical", "high", "medium"], [45, 45, 10]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [3, 77, 20],
        ),
        "software": ["postgresql", "mysql", "redis", "openssl"],
    },
    "application_server": {
        "weight": 20,
        "criticality": (["critical", "high", "medium"], [20, 55, 25]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [35, 55, 10],
        ),
        "software": ["tomcat", "django", "nodejs", "openssl", "php"],
    },
    "employee_workstation": {
        "weight": 30,
        "criticality": (["high", "medium", "low"], [10, 60, 30]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [10, 75, 15],
        ),
        "software": ["openssl", "nodejs", "jquery"],
    },
    "developer_workstation": {
        "weight": 12,
        "criticality": (["high", "medium", "low"], [25, 60, 15]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [20, 65, 15],
        ),
        "software": ["openssl", "nodejs", "django", "php", "jquery"],
    },
    "network_appliance": {
        "weight": 8,
        "criticality": (["critical", "high", "medium"], [25, 60, 15]),
        "exposure": (
            ["internet-facing", "internal", "restricted"],
            [25, 60, 15],
        ),
        "software": ["openssl", "nginx"],
    },
}

BUSINESS_UNITS = [
    "Finance", "Human Resources", "Engineering", "IT Operations",
    "Payments", "Customer Support", "Research",
]

ENVIRONMENTS = ["production", "staging", "development", "test"]
ENVIRONMENT_WEIGHTS = [55, 15, 20, 10]


def weighted_choice(rng, choices, weights):
    """Select one value using the supplied relative weights."""
    return rng.choices(choices, weights=weights, k=1)[0]


def write_csv(path, rows, fieldnames):
    """Write rows to a CSV file with a consistent column order."""
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate_assets(count, seed):
    """Generate asset records and their software installations."""
    rng = random.Random(seed)

    assets = []
    installations = []

    profile_names = list(PROFILES)
    profile_weights = [PROFILES[name]["weight"] for name in profile_names]

    for i in range(1, count + 1):
        asset_id = f"AST-{i:06d}"
        asset_type = weighted_choice(
            rng, profile_names, profile_weights
        )
        profile = PROFILES[asset_type]

        criticality = weighted_choice(
            rng, *profile["criticality"]
        )
        exposure = weighted_choice(
            rng, *profile["exposure"]
        )
        environment = weighted_choice(
            rng,
            ENVIRONMENTS,
            ENVIRONMENT_WEIGHTS,
        )

        assets.append({
            "asset_id": asset_id,
            "asset_type": asset_type,
            "business_unit": rng.choice(BUSINESS_UNITS),
            "criticality": criticality,
            "exposure": exposure,
            "environment": environment,
            "data_origin": "synthetic",
        })

        # Generate 2–4 distinct software installations per asset,
        # or fewer when its profile contains fewer products.
        software_count = min(
            len(profile["software"]),
            rng.randint(2, 4),
        )
        selected = rng.sample(profile["software"], software_count)

        for software_key in selected:
            product = SOFTWARE[software_key]
            version = rng.choice(product["versions"])

            cpe = (
                f"cpe:2.3:a:{product['vendor']}:"
                f"{product['product']}:{version}:*:*:*:*:*:*:*"
            )

            installations.append({
                "installation_id": f"SWI-{len(installations) + 1:07d}",
                "asset_id": asset_id,
                "software_vendor": product["vendor"],
                "software_product": product["product"],
                "software_name": product["name"],
                "software_version": version,
                "cpe23_uri": cpe,
                "data_origin": "synthetic",
            })

    return assets, installations


def main():
    parser = argparse.ArgumentParser(
        description="Generate PRIORIS synthetic enterprise data."
    )
    parser.add_argument(
        "--assets",
        type=int,
        default=1000,
        help="Number of assets to generate (default: 1000).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Directory for generated CSV files.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing existing generated CSV files.",
    )
    args = parser.parse_args()

    if args.assets < 1:
        parser.error("--assets must be at least 1.")

    output_dir = args.output_dir.resolve()
    assets_path = output_dir / "enterprise_assets.csv"
    software_path = output_dir / "software_inventory.csv"

    existing = [
        path for path in (assets_path, software_path)
        if path.exists()
    ]
    if existing and not args.force:
        parser.error(
            "Output already exists; refusing to overwrite: "
            + ", ".join(str(path) for path in existing)
            + ". Use --force only if you intend to replace it."
        )

    assets, installations = generate_assets(args.assets, args.seed)
    output_dir.mkdir(parents=True, exist_ok=True)

    write_csv(
        assets_path,
        assets,
        [
            "asset_id", "asset_type", "business_unit",
            "criticality", "exposure", "environment", "data_origin",
        ],
    )
    write_csv(
        software_path,
        installations,
        [
            "installation_id", "asset_id", "software_vendor",
            "software_product", "software_name", "software_version",
            "cpe23_uri", "data_origin",
        ],
    )

    print("PRIORIS — Synthetic Enterprise Generator")
    print(f"Assets generated: {len(assets)}")
    print(f"Software installations generated: {len(installations)}")
    print(f"Random seed: {args.seed}")
    print(f"Assets file: {assets_path}")
    print(f"Software file: {software_path}")
    print("Data origin: synthetic")
    print("Note: CPE identifiers require validation before vulnerability matching.")


if __name__ == "__main__":
    main()
