FROM ubuntu:22.04

MAINTAINER anonymous
RUN apt-get update

RUN useradd -m chodan

# RUN apt-get update --fix-missing -y

# RUN apt-get install -y apt-utils software-properties-common

# RUN apt-get install -y build-essential \
#         socat 
RUN apt-get install -y socat

WORKDIR /home/main

ADD ./flag /
ADD ./main /home/main

RUN chmod +x /home/main/main
ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/main/main,stderr"]

EXPOSE 1337