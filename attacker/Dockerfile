FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y sshpass openssh-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY brute.sh /brute.sh
RUN sed -i 's/\r$//' /brute.sh && chmod +x /brute.sh
CMD ["sleep", "infinity"]
