#!/usr/bin/env pipenv-shebang
# coding:utf8

"""
This script check if two GCP role are overlapping (same permissions on both roles) 
"""

import argparse
import os
from pprint import pformat
import yaml
import sys

STORAGE_FILE = f"{os.path.dirname(os.path.realpath(__file__))}/roles.yaml"


def load_roles_dict():
    with open(STORAGE_FILE, "r", encoding="UTF-8") as storage_file:
        return yaml.safe_load(storage_file.read())


def parse_args():
    clean_args = {}
    parser = argparse.ArgumentParser(description="check if 2 roles are overlapping")
    parser.add_argument(
        "-r",
        "--roles_title",
        type=str,
        help="roles title (pretty name), comma separated values",
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

    clean_args["roles"] = [role.strip() for role in args.roles_title.split(",")]
    if not clean_args["roles"]:
        print("ERROR: arg roles is empty.")
        sys.exit(-1)
    if len(clean_args["roles"]) != 2:
        print(
            "ERROR: you should provide exactly 2 roles to compare separate with a comma."
        )
        sys.exit(-1)

    clean_args["store"] = args.store
    return clean_args


def match_pretty_name_with_role_dict_or_exit(clean_args, roles_dict):
    matched_dict = []
    for role in roles_dict:
        for arg_role in clean_args["roles"]:
            if arg_role == roles_dict[role]["title"]:
                matched_dict.append(roles_dict[role])
    if len(matched_dict) != len(clean_args["roles"]):
        print(
            f"Error: one or more roles not found, check pretty name roles. {clean_args['roles']}"
        )
        sys.exit(-1)

    return matched_dict


def compare_permissions(matched_dict):
    sort_by_nb_permissions = sorted(
        matched_dict, key=lambda d: d["nb_permissions"], reverse=True
    )
    unmatched_permission = []

    for permission in sort_by_nb_permissions[1]["permissions"]:
        if permission not in sort_by_nb_permissions[0]["permissions"]:
            unmatched_permission.append(permission)

    if not unmatched_permission:
        print(
            f"'{sort_by_nb_permissions[0]['title']}' permissions is overlapping '{sort_by_nb_permissions[1]['title']}' permissions."
        )
    else:
        print(
            f"{unmatched_permission} not found in {sort_by_nb_permissions[0]['title']}"
        )


def main():
    clean_args = parse_args()
    roles_dict = load_roles_dict()
    matched_dict = match_pretty_name_with_role_dict_or_exit(clean_args, roles_dict)
    compare_permissions(matched_dict)


if __name__ == "__main__":
    main()
