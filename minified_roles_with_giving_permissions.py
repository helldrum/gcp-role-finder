#!/usr/bin/env pipenv-shebang
# coding:utf8

"""
This script get a list of fine grain permission and attempt to find the smaller roles with all those permission. 
"""

import argparse
import os
import yaml

from googleapiclient import discovery
import google.auth
import google.auth.transport.requests

STORAGE_FILE = f"{os.path.dirname(os.path.realpath(__file__))}/roles.yaml"


def parse_args():
    clean_args = {}
    parser = argparse.ArgumentParser(
        description="Find roles with the least permissions for a given set of permissions"
    )
    parser.add_argument(
        "-p",
        "--permissions",
        nargs="+",
        type=str,
        help="the permissions you want to match,separated with a comma",
        required=True,
    )

    parser.add_argument(
        "-s",
        "--store",
        type=bool,
        help="refresh store data",
        default=False,
        required=False,
    )

    args = parser.parse_args()
    clean_args["permissions"] = str(args.permissions[0]).split(",")
    clean_args["store"] = args.store
    return clean_args


def store_all_roles_and_permission_if_needed(store):
    if not os.path.isfile(STORAGE_FILE) or store:
        print("refreshing local file permission")
        refresh_storage_file()
    else:
        print("use local file to search permission")


def refresh_storage_file():
    roles_dict = {}

    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    gcp_iam_api = discovery.build("iam", "v1", credentials=credentials)
    request = gcp_iam_api.roles().list()

    while request:
        response = request.execute()
        for role in response.get("roles", []):
            request_detailed = gcp_iam_api.roles().get(name=role["name"])
            detailed_role = request_detailed.execute()
            roles_dict[detailed_role["name"]] = {
                "title": detailed_role["title"],
                "nb_permissions": len(detailed_role.get("includedPermissions", [])),
                "permissions": detailed_role.get("includedPermissions", []),
                "description": detailed_role.get("description", ""),
            }
            request = gcp_iam_api.roles().list_next(
                previous_request=request, previous_response=response
            )
    with open(STORAGE_FILE, "w", encoding="UTF-8") as storage_file:
        storage_file.write(yaml.dump(roles_dict))


def load_roles_dict():
    with open(STORAGE_FILE, "r", encoding="UTF-8") as storage_file:
        return yaml.safe_load(storage_file.read())


def match_permissions_with_local_file(permissions, roles_dict):
    print(f"Searching for roles with permissions: {permissions}")
    matched_roles = {}
    for role_name, role_info in roles_dict.items():
        role_permissions = role_info.get("permissions", [])
        if all(permission in role_permissions for permission in permissions):
            matched_roles[role_name] = role_info
    return matched_roles


def format_and_print_result(matched_roles):
    if not matched_roles:
        print("No roles found matching the given permissions.")
        return

    # find the least permissive role
    min_permissions_role = min(
        matched_roles.values(), key=lambda x: len(x["permissions"])
    )
    print(
        f"""\nRole with the least permissions: {min_permissions_role.get('nb_permissions')}\n
Title: {min_permissions_role['title']}\nDescription: {min_permissions_role.get('description')}"""
    )

    if len(min_permissions_role["permissions"]) > 30:
        print(
            f"Too many permissions ({len(min_permissions_role['permissions'])}), not printing the list"
        )
    else:
        print("Permissions:")
        for permission in min_permissions_role["permissions"]:
            print(f"- {permission}")


def main():
    clean_args = parse_args()
    store_all_roles_and_permission_if_needed(store=clean_args["store"])
    roles_dict = load_roles_dict()

    matched_roles = match_permissions_with_local_file(
        clean_args["permissions"], roles_dict
    )
    format_and_print_result(matched_roles)


if __name__ == "__main__":
    main()
