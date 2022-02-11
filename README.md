# gcp-role-finder

tool use to help to match a find grained permission to a gcp roles

this script read a local yaml with all the roles and associate permission to match permission with roles

the script retrieve permission from the most privileged roles to the least

the last three roles will have the permissions listed in order to help you to make a choice. 

# installation

you need to have gcloud installed (since we will use default gcloud creds to auth to GCP API)

clone the repository

you need to have pipenv and pipenv-shebang installed on system level and run pipenv install

```
pipenv shell

# in order to activate the virtualenv
```
# configuration

You need to set an application default configuration on gcloud to allow the script to authenticate to GCP

```
 gcloud auth application-default login 
```

# run the script

you need to provide a permission name to search

```
./gcp_permission_finder.py --permission="artifactregistry.dockerimages.list"
```

# optional regenerate store file

from time to time you should regenerate the local file with permission in order to update the new GCP roles
```
./gcp_permission_finder.py --permission="artifactregistry.dockerimages.list" --store=True
```

