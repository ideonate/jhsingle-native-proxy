FROM python:3.7
RUN pip3 install \
    jhsingle-native-proxy>=0.0.10 \
    voila \
    ipywidgets numpy matplotlib

# create a user, since we don't want to run as root
RUN useradd -m jovyan
ENV HOME=/home/jovyan
WORKDIR $HOME
USER jovyan

EXPOSE 8888

COPY Presentation.ipynb $HOME

CMD ["jhsingle-native-proxy", "--destport", "8505", "voila", "/home/jovyan/Presentation.ipynb", "{--}port={port}", "{--}no-browser", "{--}Voila.base_url={base_url}/", "{--}Voila.server_url=/"]

