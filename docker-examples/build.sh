#!/bin/bash

cd "${0%/*}"

cd jupyterhub-singleuser-streamlit-native

docker build -t ideonate/jupyterhub-singleuser-streamlit-native .
