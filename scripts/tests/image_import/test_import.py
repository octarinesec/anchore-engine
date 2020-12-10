#!/usr/bin/env python3

"""
Simple example of an import flow of data output from `syft docker:nginx --output json` into Anchore. Uses syft v0.8.0 output.
"""

import sys
import requests
import json
import base64

JSON_HEADER = {"Content-Type": "application/json"}
ENDPOINT = "http://localhost"

# Defaults... don"t use these
AUTHC = ("admin", "foobar")


# The input file with the syft output sbom
syft_package_sbom = sys.argv[1]
if not syft_package_sbom:
    raise Exception("Must have valid input file as arg 1")

# Load other types from the input

# Always load from user input
dockerfile = sys.argv[2]

# Generate/fetch from syft/skopeo?
manifest = sys.argv[3] if len(sys.argv) > 3 else None

# Generate/fetch from syft/skopeo?
parent_manifest = sys.argv[4] if len(sys.argv) > 4 else None

# Get from syft output
image_config = sys.argv[5] if len(sys.argv) > 5 else None


def check_response(api_resp: requests.Response) -> dict:
    print("Got response: {}".format(api_resp.status_code))
    print("Payload: {}".format(api_resp.json()))
    if api_resp.status_code != 200:
        sys.exit(1)

    resp_payload = api_resp.json()
    return resp_payload


def init_operation():
    print("Creating import operation")
    resp = requests.post(ENDPOINT + "/imports/images", auth=AUTHC)

    # There are other fields present, such as "expires_at" timestamp, but all we need to proceed is the operation"s uuid.
    operation_id = check_response(resp).get("uuid")
    return operation_id


def extract_syft_metadata(path):
    with open(path) as f:
        sbom_content = bytes(f.read(), "utf-8")

    print("Loaded content from file: {}".format(path))
    # Parse into json to extract some info
    parsed = json.loads(str(sbom_content, "utf-8"))
    digest = parsed["source"]["target"][
        "digest"
    ]  # This is the image id, use it as digest since syft doesn't get a digest from a registry
    local_image_id = parsed["source"]["target"]["digest"]
    tags = parsed["source"]["target"]["tags"]

    return digest, local_image_id, tags


# NOTE: in these examples we load from the file as bytes arrays instead of json objects to ensure that the digest computation matches and
# isn't impacted by any python re-ordering of keys or adding/removing whitespace. This should enable the output of `sha256sum <file>` to match the digests returned during this test
def upload_content(path, content_type, operation_id):
    with open(path) as f:
        content = bytes(f.read(), "utf-8")
    print("Loaded {} content from {}".format(content_type, path))

    print("Uploading {}".format(content_type))
    resp = requests.post(
        ENDPOINT + "/imports/images/{}/{}".format(operation_id, content_type),
        data=content,
        headers=JSON_HEADER
        if content_type in ["manifest", "parent_manifest", "packages", "image_config"]
        else None,
        auth=AUTHC,
    )
    content_digest = check_response(resp).get("digest")
    return content_digest


# Step 1: Initialize the operation, get an operation ID
operation_id = init_operation()

# Step 2: Upload the analysis content types
image_digest, local_image_id, tags = extract_syft_metadata(syft_package_sbom)
packages_digest = upload_content(syft_package_sbom, "packages", operation_id)
dockerfile_digest = upload_content(dockerfile, "dockerfile", operation_id)
manifest_digest = upload_content(manifest, "manifest", operation_id)
image_config_digest = upload_content(image_config, "image_config", operation_id)
parent_manifest_digest = upload_content(
    parent_manifest, "parent_manifest", operation_id
)

# Construct the type-to-digest map
contents = {
    "packages": packages_digest,
    "dockerfile": dockerfile_digest,
    "manifest": manifest_digest,
    "parent_manifest": parent_manifest_digest,
    "image_config": image_config_digest,
}

# Step 3: Complete the import by generating the import manifest which includes the conetnt reference as well as other metadata
# for the image such as digest, annotations, etc
add_payload = {
    "source": {
        "import": {
            "digest": image_digest,
            # "parent_digest": None,
            "local_image_id": local_image_id,
            "contents": contents,
            "tags": tags,
            "operation_uuid": operation_id,
        }
    }
}

# Step 4: Add the image for processing the import via the analysis queue
print("Adding image/finalizing")
resp = requests.post("http://localhost/images", json=add_payload, auth=AUTHC)
result = check_response(resp)

# Step 5: Verify the image record now exists
print("Checking image list")
resp = requests.get(
    "http://localhost/images/{digest}".format(digest=image_digest), auth=AUTHC
)
images = check_response(resp)

# Check for finished
print("Completed successfully!")
