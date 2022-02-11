#!/usr/bin/env python3
# coding:utf8

import argparse

from googleapiclient import discovery
from oauth2client.client import GoogleCredentials


def parse_args():
    clean_args = {}
    parser = argparse.ArgumentParser(
        description="the permission you want to find in role"
    )
    parser.add_argument(
        "-p",
        "--permission",
        type=str,
        help="an integer for the accumulator",
        required=True,
    )

    args = parser.parse_args()

    clean_args["permission"] = args.permission.strip()
    return clean_args


def fetch_all_gcp_roles_and_match_permission(permission):

    print(f"searching for permission {permission} in all GCP roles")

    credentials = GoogleCredentials.get_application_default()
    gcp_iam_api = discovery.build("iam", "v1", credentials=credentials)
    request = gcp_iam_api.roles().list()

    while request:
        response = request.execute()
        for role in response.get("roles", []):
            print_detailed_role_by_role_name(
                permission=permission, role_name=role["name"], gcp_iam_api=gcp_iam_api
            )
        request = gcp_iam_api.roles().list_next(
            previous_request=request, previous_response=response
        )


def print_detailed_role_by_role_name(permission, role_name, gcp_iam_api):
    request_detailed = gcp_iam_api.roles().get(name=role_name)
    detailed_role = request_detailed.execute()
    try:
        if permission in detailed_role["includedPermissions"]:
            print(
                f"""\n{detailed_role["name"]}  {detailed_role["title"]}
found {len(detailed_role['includedPermissions'])} permission(s) for this role
{detailed_role["description"]}\n"""
            )
    except:
        pass # no permission on this role

def main():
    clean_args = parse_args()
    fetch_all_gcp_roles_and_match_permission(clean_args["permission"])


if __name__ == "__main__":
    main()
