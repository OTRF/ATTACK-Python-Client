# ATTACK Python Client script: Jupyter Environment Dockerfile

FROM jupyter/base-notebook
LABEL maintainer="Jupyter Project <jupyter@googlegroups.com>"

RUN python3 -m pip install --upgrade six attackcti pandas altair vega

COPY docs/intro.ipynb ${HOME}/docs/
COPY docs/playground ${HOME}/docs/playground
COPY docs/presentations ${HOME}/docs/presentations

USER ${NB_UID}
WORKDIR ${HOME}
