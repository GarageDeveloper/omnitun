# A Linux machine with systemd, to install the service as README.md says
# and run it under packaging/omnitund.service (see README.md here).
FROM ubuntu:24.04
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -qy --no-install-recommends \
        systemd systemd-sysv systemd-resolved dbus dbus-user-session iproute2 iptables iputils-ping \
        wireguard-tools gnome-keyring sudo util-linux >/dev/null \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
