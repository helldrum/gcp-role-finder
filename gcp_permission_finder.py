#!/usr/bin/env python3
# coding:utf8

import argparse
import os
from pprint import pformat
import yaml

from googleapiclient import discovery
import google.auth
import google.auth.transport.requests

STORAGE_FILE = f"{os.path.dirname(os.path.realpath(__file__))}/roles.yaml"


def parse_args():
    clean_args = {}
    parser = argparse.ArgumentParser(
        description="the permission you want to find in role"
    )
    parser.add_argument(
        "-p",
        "--permission",
        type=str,
        help="the permission you want to match",
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

    clean_args["permission"] = args.permission.strip()
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


def match_permission_with_local_file(permission, roles_dict, matched_dict):
    print(f"searching for permission {permission} in all GCP roles")
    for role_name in roles_dict:
        try:
            if permission in roles_dict[role_name].get("permissions"):
                matched_dict[role_name] = roles_dict[role_name]
        except TypeError:
            pass
    return matched_dict


def format_and_print_result(matched_dict):

    # sort and reverse roles by nb permissions
    reversed_permissions_nbs = (
        tuple(
            sorted(
                [(matched_dict[role]["nb_permissions"], role) for role in matched_dict]
            )
        )
    )[::-1]

    # print all roles - last 3 roles without permissions
    for i in range(0, len(reversed_permissions_nbs) - 3):
        role_name = reversed_permissions_nbs[i][1]
        print(
            f"""\n{role_name}  {matched_dict[role_name]["title"]}
found {matched_dict[role_name]['nb_permissions']} permission(s) for this role
{matched_dict[role_name].get("description")}"""
        )

    for i in range(len(reversed_permissions_nbs) - 3, len(reversed_permissions_nbs)):
        role_name = reversed_permissions_nbs[i][1]
        print(
            f"""\n{role_name}  {matched_dict[role_name]["title"]}
found {matched_dict[role_name]['nb_permissions']} permission(s) for this role
{matched_dict[role_name].get("description")}\n
{pformat(matched_dict[role_name].get("permissions"))}\n
"""
        )


def main():
    clean_args = parse_args()
    store_all_roles_and_permission_if_needed(store=clean_args["store"])
    roles_dict = load_roles_dict()

    matched_dict = {}
    matched_dict = match_permission_with_local_file(
        permission=clean_args["permission"],
        roles_dict=roles_dict,
        matched_dict=matched_dict,
    )
    format_and_print_result(matched_dict)


if __name__ == "__main__":
    main()
