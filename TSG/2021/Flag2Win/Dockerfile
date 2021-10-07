FROM ubuntu:20.04
RUN mkdir Flag2Win
COPY flag_to_win.rb /Flag2Win
COPY start.sh /Flag2Win
RUN apt-get update
RUN apt-get install -y ruby-full gcc build-essential zlib1g-dev libssl-dev
RUN apt-get install -y socat
RUN gem install openssl
RUN chmod 777 /Flag2Win/start.sh

EXPOSE 35719
ENTRYPOINT ["/Flag2Win/start.sh"] 
