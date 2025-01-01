#!/bin/bash

# import .env file
set -a && source .env && set +a

act --artifact-server-path .act_artifacts
