# ATTACK Python Client script: Jupyter Environment Dockerfile

ARG OWNER=jupyter
ARG BASE_CONTAINER=$OWNER/base-notebook
FROM $BASE_CONTAINER

LABEL maintainer="Jupyter Project <jupyter@googlegroups.com>"

# Fix: https://github.com/hadolint/hadolint/wiki/DL4006
# Fix: https://github.com/koalaman/shellcheck/wiki/SC3014
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

USER root

# Install all OS dependencies for fully functional notebook server
RUN apt-get update --yes && \
    apt-get install --yes --no-install-recommends

RUN python3 -m pip install --upgrade six==1.15.0 attackcti==0.3.8 pandas==1.3.5 altair vega

COPY docs/playground ${HOME}/

# Switch back to jovyan to avoid accidental container runs as root
USER ${NB_UID}

WORKDIR ${HOME}