# ATTACK Python Client script: Jupyter Environment Dockerfile
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: GPL-3.0

FROM cyb3rward0g/jupyter-base:0.0.3
LABEL maintainer="Roberto Rodriguez @Cyb3rWard0g"
LABEL description="Dockerfile ThreatHunter Playbook Project."

ARG NB_USER
ARG NB_UID
ENV NB_USER jovyan
ENV NB_UID 1000
ENV HOME /home/${NB_USER}

USER root

RUN adduser --disabled-password \
    --gecos "Default user" \
    --uid ${NB_UID} \
    ${NB_USER} \
    && python3 -m pip install attackcti==0.2.7 altair vega

COPY notebooks/ ${HOME}

RUN chown -R ${NB_USER}:${NB_USER} ${HOME} ${JUPYTER_DIR}

USER ${NB_USER}

WORKDIR ${HOME}