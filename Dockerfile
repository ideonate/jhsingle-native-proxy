# A streamlit example for JupyterHub

FROM python:3.7

RUN mkdir /tmp/jhsingle_current

ADD . /tmp/jhsingle_current/

RUN cd /tmp/jhsingle_current && pip3 install -e .

RUN pip3 install streamlit

# create a user, since we don't want to run as root
RUN useradd -m jovyan
ENV HOME=/home/jovyan
WORKDIR $HOME
USER jovyan

EXPOSE 8888

WORKDIR /app

CMD ["jhsingle-native-proxy", "--destport", "8505", "streamlit", "hello", "{--}server.port", "{port}", "{--}server.headless", "True", "{--}server.enableCORS", "False"]
